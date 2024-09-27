#include "ssl_server.h"

#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <sstream>
#include "base64.h"

#include "dh.h"
#include "integer.h"
#include "osrng.h"

#include "crypto_adaptor.h"
#include "tcp.h"
#include "logger.h"
#include "utils.h"

using namespace std;

SslServer::SslServer() {
  string datetime;
  if ( get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0 ) {
    exit(1);
  }
  this->logger_ = new Logger(("ssl_server_"+datetime+".log"));
  this->tcp_->set_logger(this->logger_);

  get_datetime(&datetime, "%Y/%m/%d %H:%M:%S");
  this->logger_->log("Server Log at " + datetime);

  this->closed_ = false;

  // init dhe
  generate_pqg(this->dh_p_, this->dh_q_, this->dh_g_);

  // init rsa
  generate_rsa_keys(this->private_key_, this->public_key_);
}

SslServer::~SslServer() {
  if ( !this->closed_ ) {
    this->shutdown();
  }
  delete this->logger_;
}


int SslServer::start(int num_clients) {
  if ( this->closed_ ) {
    return -1;
  }

  return this->tcp_->socket_listen(num_clients);
}

// FUNCTIONS DEFINED BY ME
vector<string> parse_responses_with_delimiter(string response, char delimiter){
  vector<string> tokens;

  size_t pos = 0;
  string token;
  while ((pos = response.find(delimiter)) != string::npos) {
    token = response.substr(0, pos);
    tokens.push_back(token);
    response.erase(0, pos + 1);
  }
  tokens.push_back(response);

  return tokens;
}

string CryptoInt_to_string(CryptoPP::Integer num){
  std::stringstream ss;
  std::string s;
  ss  << hex << num;
  
  s = ss.str();

  return s;
}

// Convert RSA public key to Base64-encoded string
std::string PublicKey_To_Base64(const CryptoPP::RSA::PublicKey& publicKey) {
    std::string publicKeyStr;
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(publicKeyStr));
    publicKey.Save(encoder);
    encoder.MessageEnd();
    return publicKeyStr;
}
std::string PrivateKey_To_Base64(const CryptoPP::RSA::PrivateKey& publicKey) {
    std::string publicKeyStr;
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(publicKeyStr));
    publicKey.Save(encoder);
    encoder.MessageEnd();
    return publicKeyStr;
}

void remove_Newlines(std::string& str) {
    // Iterate over each character in the string
    for (size_t i = 0; i < str.length(); ++i) {
        // If the character is a newline ('\n') or carriage return ('\r'), remove it
        if (str[i] == '\n' || str[i] == '\r') {
            str.erase(i, 1); // Erase the character at index i
            --i; // Adjust the index to account for the erased character
        }
    }
}

std::string encodeBase64(const std::string& s)
{
    std::string encoded;
    CryptoPP::StringSource(s, true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded)
        )
    );
    return encoded;
}

std::string decodeBase64(const std::string& encoded)
{
    std::string decoded;
    CryptoPP::StringSource(encoded, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(decoded)
        )
    );
    return decoded;
}

std::string generateRandom(int length)
{
    CryptoPP::AutoSeededRandomPool rng;
    byte randomBytes[length];
    rng.GenerateBlock(randomBytes, length);

    std::string randomString(randomBytes, randomBytes + length);
    return randomString;
}

std::string createMasterKey(const std::string& string1, const std::string& string2, const std::string& string3)
{
    std::string concatenated = string1 + string2 + string3;

    // Encode the concatenated string in Base64
    CryptoPP::Base64Encoder encoder;
    encoder.Put(reinterpret_cast<const byte*>(concatenated.data()), concatenated.size());
    encoder.MessageEnd();

    // Get the encoded string
    std::string masterKey;
    size_t size = encoder.MaxRetrievable();
    masterKey.resize(size);
    encoder.Get(reinterpret_cast<byte*>(&masterKey[0]), size);

    return masterKey;
}

SSL* SslServer::accept() {
  if ( this->closed_ ) {
    return NULL;
  }

  TCP* cxn = this->tcp_->socket_accept();
  if ( cxn == NULL ) {
    cerr << "error when accepting" << endl;
    return NULL;
  }

  cxn->set_logger(this->logger_);

  SSL* new_ssl_cxn = new SSL(cxn);
  this->clients_.push_back(new_ssl_cxn);

  // IMPLEMENT HANDSHAKE HERE
  // ############################################################
  // #                   RECIEVE CLIENT HELLO                   #
  // ############################################################
  SslServer::Record client_record;
  new_ssl_cxn->recv(&client_record);
  string recieved_data(client_record.data);
  string connection_type = recieved_data;
  connection_type = connection_type.substr(0,3);

  // ############################################################
  // #                 DATA FOR AUTHENTICATION                  #
  // ############################################################
  string SERVER_SIGNATURE = "ServerSignature";
  string DIGITAL_SIGNATURE_OF_CLIENT_SENT_BY_CA = "ClientSignature";

  if(connection_type=="DHE"){
    // ############################################################
    // #        SEND SERVER HELLO WITH SERVER's PUBLIC KEY        #
    // ############################################################
    CryptoPP::AutoSeededRandomPool rnd;
    CryptoPP::Integer private_key_server_dhe(rnd, CryptoPP::Integer::One(), CryptoPP::Integer::One());
      // Generate Public Key
    CryptoPP::Integer public_key_server_dhe = a_exp_b_mod_c(this->dh_g_, private_key_server_dhe, this->dh_p_);

    SSL::Record server_hello;
    string d = CryptoInt_to_string(this->dh_p_)+"_"+CryptoInt_to_string(this->dh_g_)+"_"+CryptoInt_to_string(public_key_server_dhe)+"_"+SERVER_SIGNATURE;
    const int length = d.length();
    char* char_array = new char[length + 1];
    strcpy(char_array, d.c_str());

    server_hello.hdr.type = HS_SERVER_HELLO;
    server_hello.hdr.version = VER_99;
    server_hello.hdr.length = length;
    server_hello.data = char_array;
    int res = new_ssl_cxn->send(server_hello);

    // ############################################################
    // #                RECEIVE CLIENT PUBLIC KEY                 #
    // ############################################################
    SslServer::Record client_public_key;
    new_ssl_cxn->recv(&client_public_key);
    vector<string> tokens = parse_responses_with_delimiter(client_public_key.data, '_');
    string recieved_data2 = tokens[0];
    string client_cert = tokens[1];

    // ############################################################
    // #                   AUTHENTICATE CLIENT                    #
    // ############################################################
    if(client_cert.substr(0, client_cert.size()-1) == "ClientSignature"){
      // cout<<"CLIENT VERIFIED"<<endl;
      this->logger_->log("===================================================");
      this->logger_->log("CLIENT VERIFIED");
      this->logger_->log("===================================================");
    }

    // ############################################################
    // #                 DERIVE SHARED MASTER KEY                 #
    // ############################################################
    this->logger_->log("===================================================");
    this->logger_->log("GENERATED COMMON KEY FOR DHE @ SERVER : ");
    this->logger_->log("===================================================");
    CryptoPP::Integer public_key_client_DHE = CryptoPP::Integer(recieved_data2.c_str());
    CryptoPP::Integer pre_master_secret = private_key_server_dhe + public_key_client_DHE;
    string d2 = CryptoInt_to_string(pre_master_secret).substr(0,16);
    const unsigned char* data2 = reinterpret_cast<const unsigned char*>(d2.c_str());

    // cout<<"==================================================="<<endl;
    // cout<<"GENERATED COMMON KEY FOR DHE @ SERVER: "<<d2<<endl;
    // cout<<"==================================================="<<endl;

    // ############################################################
    // #          SET SHARED KEY TO BEGIN COMMUNICATION           #
    // ############################################################
    new_ssl_cxn->set_shared_key(data2, d2.size());

    if(res > -1){
      return new_ssl_cxn;
    }
  }
  else if(connection_type=="RSA"){
    // ############################################################
    // #        SEND SERVER HELLO & CERTIFICATE TO CLIENT         #
    // ############################################################
    string SERVER_RANDOM = generateRandom(16);

    string encodedPriv, encodedPub;
    CryptoPP::Base64Encoder privKeySink(new CryptoPP::StringSink(encodedPriv));
    this->private_key_.DEREncode(privKeySink);
    privKeySink.MessageEnd();
    
    CryptoPP::Base64Encoder pubKeySink(new CryptoPP::StringSink(encodedPub));
    this->public_key_.DEREncode(pubKeySink);
    pubKeySink.MessageEnd();


    // ############################################################
    // #           SEND HELLO TO CLIENT WITH SIGNATURE            #
    // ############################################################
    SSL::Record server_hello;
    string d = encodedPub+"_"+SERVER_SIGNATURE+"_"+encodeBase64(SERVER_RANDOM);
    const int length = d.length();
    char* char_array = new char[length + 1];
    strcpy(char_array, d.c_str());

    server_hello.hdr.type = HS_SERVER_HELLO;
    server_hello.hdr.version = VER_99;
    server_hello.hdr.length = length;
    server_hello.data = char_array;
    int res = new_ssl_cxn->send(server_hello);

    // ############################################################
    // #   RECEIVE PRE-MASTER SECRET & CERTIFICATE FROM CLIENT    #
    // ############################################################
    SSL::Record client_secret;
    new_ssl_cxn->recv(&client_secret);
    string rec_data = client_secret.data;
    vector<string> tokens2 = parse_responses_with_delimiter(rec_data, '_');
    string cipher = decodeBase64(tokens2[0]);
    string CLIENT_RANDOM = decodeBase64(tokens2[1]);
    string client_cert = tokens2[2];

    // ############################################################
    // #                   AUTHENTICATE CLIENT                    #
    // ############################################################
    if(client_cert == DIGITAL_SIGNATURE_OF_CLIENT_SENT_BY_CA){
      // cout<<"CLIENT VERIFIED"<<endl;
      this->logger_->log("===================================================");
      this->logger_->log("CLIENT VERIFIED");
      this->logger_->log("===================================================");
    }

    // Decrypt Client's pre-master secret
    string plain_master;
    rsa_decrypt(this->private_key_, &plain_master, cipher);

    // ############################################################
    // #                   GENERATE MASTER KEY                    #
    // ############################################################
    this->logger_->log("===================================================");
    this->logger_->log("GENERATED MASTER KEY FOR RSA @ SERVER : ");
    this->logger_->log("===================================================");
    string master_key = createMasterKey(plain_master, SERVER_RANDOM, CLIENT_RANDOM).substr(0,16);

    const unsigned char* data_RSA = reinterpret_cast<const unsigned char*>(master_key.c_str());

    // cout<<"==================================================="<<endl;
    // cout<<"GENERATED MASTER KEY FOR RSA @ SERVER: "<<master_key<<endl;
    // cout<<"==================================================="<<endl;

    // ############################################################
    // #          SET SHARED KEY TO BEGIN COMMUNICATION           #
    // ############################################################
    new_ssl_cxn->set_shared_key(data_RSA, master_key.size());

    if(res > -1){
      return new_ssl_cxn;
    }

  }

  return NULL;
}

int SslServer::shutdown() {
  if ( this->closed_ ) {
    return -1;
  }

  // pop all clients
  while ( !this->clients_.empty() ) {
    SSL* cxn = this->clients_.back();
    this->clients_.pop_back();
    if ( cxn != NULL ) {
      delete cxn;
    }
  }
  return 0;
}

vector<SSL*> SslServer::get_clients() const {
  return vector<SSL*>(this->clients_);
}

int SslServer::broadcast(const string &msg) {
  if ( this->closed_ ) {
    return -1;
  }

  int num_sent = 0;

  // this->logger_->log("broadcast:");
  // this->logger_->log_raw(msg);

  for ( vector<SSL*>::iterator it = this->clients_.begin() ;
        it != this->clients_.end() ; ++it ) {
    ssize_t send_len;
    send_len = (*it)->send(msg);
    if ( send_len == (unsigned int)msg.length() ) {
      num_sent += 1;
    }
  }

  return num_sent;
}
