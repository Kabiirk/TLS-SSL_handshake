#include "ssl_client.h"

#include "stdlib.h"
#include "string.h"

#include <iostream>
#include <sstream>
#include <vector>

#include "dh.h"
#include "integer.h"
#include "osrng.h"
#include "base64.h"

#include "tcp.h"
#include "crypto_adaptor.h"
#include "logger.h"
#include "utils.h"

using namespace std;

SslClient::SslClient() {
  string datetime;
  if ( get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0 ) {
    exit(1);
  }
  this->logger_ = new Logger(("ssl_client_"+datetime+".log"));
  this->tcp_->set_logger(this->logger_);

  get_datetime(&datetime, "%Y/%m/%d %H:%M:%S");
  this->logger_->log("Client Log at " + datetime);


}

SslClient::~SslClient() {
  if ( this->logger_ ) {
    delete this->logger_;
    this->logger_ = NULL;
    this->tcp_->set_logger(NULL);
  }
}

// Custom functions
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
  stringstream ss;
  string s;
  ss << hex << num;
  
  s = ss.str();

  return s;
}


// Convert Base64-encoded string to RSA public key
CryptoPP::RSA::PublicKey Base64_To_PublicKey(const std::string& publicKeyBase64) {
    CryptoPP::RSA::PublicKey publicKey;

    // Decode the Base64-encoded string
    CryptoPP::StringSource publicKeySource(publicKeyBase64, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::ArraySink((byte*)&publicKey, sizeof(publicKey))
        )
    );

    return publicKey;
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

int SslClient::connect(const std::string &ip, int port, uint16_t cxntype) {

  // connect
  if ( this->tcp_->socket_connect(ip, port) != 0 ) {
    cerr << "Couldn't connect TCP" << endl;
    return -1;
  }

  // IMPLEMENT HANDSHAKE HERE
  // ############################################################
  // #         SEND CLIENT HELLO TO SERVER (RSA & DHE)          #
  // ############################################################
  SSL::Record client_hello;
  string d = (cxntype == 0x0000) ? "DHE" : "RSA" ;
  int length = d.length();
  char* char_array = new char[length];
  string a = d;
  strcpy(char_array, d.c_str());

  client_hello.hdr.type = HS_CLIENT_HELLO;
  client_hello.hdr.version = VER_99;
  client_hello.hdr.length = length;
  client_hello.data = char_array;
  int res = this->send(client_hello);

  // ############################################################
  // #              SETUP DATA FOR AUTHENTICATION               #
  // ############################################################
  string DIGITAL_SIGNATURE_OF_SERVER_SENT_BY_CA = "ServerSignature";
  string CLIENT_SIGNATURE = "ClientSignature";


  if(d == "DHE"){
    // ############################################################
    // #                  RECEIVE SERVER HELLO                    #
    // ############################################################

    // ############################################################
    // #   OBTAIN p, g, SERVER PUBLIC KEY & SERVER CERTIFICATE    #
    // ############################################################
    SSL::Record server_hello;
    this->recv(&server_hello);
    string recieved_data = server_hello.data;
    vector<string> tokens = parse_responses_with_delimiter(recieved_data, '_');

    //P
    CryptoPP::Integer dh_p_ = CryptoPP::Integer(tokens[0].c_str());
    // G
    CryptoPP::Integer dh_g_ = CryptoPP::Integer(tokens[1].c_str());
    // SERVER PUBLIC KEY
    CryptoPP::Integer public_key__server_dhe = CryptoPP::Integer(tokens[2].c_str());
    // SERVER CERTIFICATE
    string server_cert = tokens[3];

    // ############################################################
    // #       AUTHENTICATE SERVER WITH CERTIFICATE FROM CA       #
    // ############################################################
    // Note: For now we are using A signature-based certificate, but
    //       normally, both a Digital Signature & a valid CA-issued
    //       Digital Certificate (usually a '.pem') file are used.
    if(server_cert == DIGITAL_SIGNATURE_OF_SERVER_SENT_BY_CA){
      // cout<<"SERVER VERIFIED"<<endl;
      this->logger_->log("===================================================");
      this->logger_->log("SERVER VERIFIED");
      this->logger_->log("===================================================");
    }

    // ############################################################
    // #                CLIENT SIDE KEY GENERATION                #
    // ############################################################
    // Generate random secret number
    CryptoPP::AutoSeededRandomPool rnd;
    // PRIVATE KEY
    CryptoPP::Integer private_key_client_dhe(rnd, CryptoPP::Integer::One(), CryptoPP::Integer::One());
    // PUBLIC KEY (using server p & g)
    CryptoPP::Integer public_key_client_dhe = a_exp_b_mod_c(dh_g_, private_key_client_dhe, dh_p_);

    // ############################################################
    // #             SEND CLIENT PUBLIC KEY TO SERVER             #
    // ############################################################
    SSL::Record client_public_key;
    d = CryptoInt_to_string(public_key_client_dhe)+"_"+CLIENT_SIGNATURE;
    length = d.length();
    char_array = new char[length + 1];
    strcpy(char_array, d.c_str());

    client_public_key.hdr.type = HS_CLIENT_KEY_EXCHANGE;
    client_public_key.hdr.version = VER_99;
    client_public_key.hdr.length = length;
    client_public_key.data = char_array;
    res = this->send(client_public_key);

    // ############################################################
    // #                 DERIVE SHARED MASTER KEY                 #
    // ############################################################
    this->logger_->log("===================================================");
    this->logger_->log("GENERATED COMMON KEY FOR DHE @ CLIENT : ");
    this->logger_->log("===================================================");
    CryptoPP::Integer pre_master_secret = private_key_client_dhe + public_key__server_dhe;
    string d2 = CryptoInt_to_string(pre_master_secret).substr(0,16);
    const unsigned char* data2 = reinterpret_cast<const unsigned char*>(d2.c_str());

    // cout<<"==================================================="<<endl;
    // cout<<"GENERATED COMMON KEY FOR DHE @ CLIENT : "<<d2<<endl;
    // cout<<"==================================================="<<endl;

    // ############################################################
    // #          SET SHARED KEY TO BEGIN COMMUNICATION           #
    // ############################################################
    this->set_shared_key(data2, d2.size());

    if(res > -1){
      return 0;
    }
  }
  else if(d == "RSA"){
    // ############################################################
    // #             GENERATE CLIENT RANDOM PARAMETER             #
    // ############################################################
    string CLIENT_RANDOM = generateRandom(16);

    // ############################################################
    // #         RECEIVE SERVER HELLO, SERVER PUBLIC KEY          #
    // ############################################################
    SSL::Record server_hello;
    int res = this->recv(&server_hello);
    string recieved_data = server_hello.data;
    vector<string> tokens = parse_responses_with_delimiter(recieved_data, '_');
    string SERVER_PUBLIC_KEY = tokens[0];
    string server_cert = tokens[1];
    string SERVER_RANDOM = decodeBase64(tokens[2]);

    // ############################################################
    // #       AUTHENTICATE SERVER WITH CERTIFICATE FROM CA       #
    // ############################################################
    // Note: For now we are using A signature-based certificate, but
    //       normally, both a Digital Signature & a valid CA-issued
    //       Digital Certificate (usually a '.pem') file are used.
    if(server_cert == DIGITAL_SIGNATURE_OF_SERVER_SENT_BY_CA){
      // cout<<"SERVER VERIFIED"<<endl;
      this->logger_->log("===================================================");
      this->logger_->log("SERVER VERIFIED");
      this->logger_->log("===================================================");
    }

    // Decode Server Public Key
    CryptoPP::RSA::PublicKey pubKeyDecoded;
    CryptoPP::StringSource ss(recieved_data, true, new CryptoPP::Base64Decoder);
    pubKeyDecoded.BERDecode(ss);

    // ############################################################
    // #           GENERATE SECRET & IT'S CIPHER STRING           #
    // ############################################################
    string cipher;
    string plain="ThisIsASecret";
    rsa_encrypt(pubKeyDecoded, &cipher, plain);
    string cipher64 = encodeBase64(cipher);

    // ############################################################
    // #        SENDING ENCRYPTED PRE-MASTER KEY TO SERVER        #
    // ############################################################
    SSL::Record client_pre_master_record;
    string d = cipher64+"_"+encodeBase64(CLIENT_RANDOM)+"_"+CLIENT_SIGNATURE;
    const int length = d.length();
    char* char_array2 = new char[length + 1];
    memcpy(char_array2, d.c_str(), length+1);

    client_pre_master_record.hdr.type = HS_CERTIFICATE;
    client_pre_master_record.hdr.version = VER_99;
    client_pre_master_record.hdr.length = length;
    client_pre_master_record.data = char_array2;
    res = this->send(client_pre_master_record);

    // ############################################################
    // #                    DERIVE MASTER KEY                     #
    // ############################################################
    this->logger_->log("===================================================");
    this->logger_->log("GENERATED MASTER KEY FOR RSA @ CLIENT : ");
    this->logger_->log("===================================================");
    string master_key = createMasterKey(plain, SERVER_RANDOM, CLIENT_RANDOM).substr(0,16);

    // ############################################################
    // #          SET SHARED KEY TO BEGIN COMMUNICATION           #
    // ############################################################
    // cout<<"==================================================="<<endl;
    // cout<<"GENERATED MASTER KEY FOR RSA @ CLIENT: "<<master_key<<endl;
    // cout<<"==================================================="<<endl;
    const unsigned char* data_RSA = reinterpret_cast<const unsigned char*>(master_key.c_str());

    this->set_shared_key(data_RSA, master_key.size());

    if(res > -1){
      return 0;
    }
    
  }

  return -1;
}

int SslClient::close() {
  int ret_code;
  ret_code = this->tcp_->socket_close();
  return ret_code;
}
