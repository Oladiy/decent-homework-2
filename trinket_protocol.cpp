#include <iostream>
#include <map>
#include <openssl/bio.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

using std::cerr;
using std::cout;
using std::endl;
using std::map;
using std::string;

namespace Command {
    const unsigned char COMMAND_OPEN_DOOR[] = "OPEN DOOR";
    const unsigned BUFFER = 65;
    const unsigned DSA_BITS = 2048;
}

class Trinket {
public:
    explicit Trinket(DSA* dsa): _dsa(dsa) {}
    Trinket(const Trinket&);
    Trinket& operator=(const Trinket& t) = delete;

    BIGNUM* get_public_key() const { return _dsa->pub_key; };
    DSA* get_dsa() const;
    DSA_SIG* sign_data(const unsigned char* data);

private:
    DSA* _dsa;
};

Trinket::Trinket(const Trinket& trinket) {
    this->_dsa = trinket._dsa;
}

DSA *Trinket::get_dsa() const {
    DSA* dsa = _dsa;
    dsa->priv_key = nullptr;
    return dsa;
}

DSA_SIG* Trinket::sign_data(const unsigned char* data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, sizeof(data));
    SHA256_Final(hash, &sha256);
    char outputBuffer[Command::BUFFER];
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[Command::BUFFER - 1] = 0;

    DSA_SIG* signed_data = DSA_do_sign(reinterpret_cast<const unsigned char *>(outputBuffer), sizeof(outputBuffer), _dsa);
    return signed_data;
}


class Car {
public:
    explicit Car(DSA* dsa): _dsa(dsa) {}
    Car(const Car&);
    Car& operator=(const Car& c) = delete;

    BIGNUM* get_public_key() const { return _dsa->pub_key; };
    DSA* get_dsa() const;
    bool verify_signature(DSA_SIG* signed_data, const unsigned char* data, DSA* trinket_dsa, const map<BIGNUM*, bool>& manufacturer_database);

private:
    DSA* _dsa;
};

bool Car::verify_signature(DSA_SIG* signed_data, const unsigned char* data, DSA* trinket_dsa, const map<BIGNUM*, bool>& manufacturer_database) {
    if (manufacturer_database.find(trinket_dsa->pub_key) == manufacturer_database.end()) {
        return false;
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, sizeof(data));
    SHA256_Final(hash, &sha256);
    char outputBuffer[Command::BUFFER];
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[Command::BUFFER - 1] = 0;

    int is_verified = DSA_do_verify(reinterpret_cast<const unsigned char *>(outputBuffer), sizeof(outputBuffer), signed_data, trinket_dsa);
    return is_verified;
}

Car::Car(const Car &car) {
    this->_dsa = car._dsa;
}

DSA* Car::get_dsa() const {
    DSA* dsa = _dsa;
    dsa->priv_key = nullptr;
    return dsa;
}


class Manufacturer {
public:
    Manufacturer() = default;
    Manufacturer(const Manufacturer&) = delete;
    Manufacturer& operator=(const Manufacturer& m) = delete;

    Trinket register_trinket();
    Car register_car();
    BIGNUM* get_trinket_public_key() const { return _trinket_public_key; };
    BIGNUM* get_car_public_key() const { return _car_public_key; };
private:
    BIGNUM* _trinket_public_key{nullptr};
    BIGNUM* _car_public_key{nullptr};
};

Trinket Manufacturer::register_trinket() {
    DSA* dsa = DSA_new();
    DSA_generate_parameters_ex(dsa, Command::DSA_BITS, nullptr, time(nullptr),
                               nullptr, nullptr, nullptr);
    DSA_generate_key(dsa);
    _trinket_public_key = dsa->pub_key;
    return Trinket{dsa};
}

Car Manufacturer::register_car() {
    DSA* dsa = DSA_new();
    DSA_generate_parameters_ex(dsa, Command::DSA_BITS, nullptr, time(nullptr),
                               nullptr, nullptr, nullptr);
    DSA_generate_key(dsa);
    _car_public_key = dsa->pub_key;
    return Car{dsa};
}


int main() {
    map <BIGNUM*, bool> manufacturer_database;
    Manufacturer manufacturer;
    Trinket trinket = manufacturer.register_trinket();
    Car car = manufacturer.register_car();

    manufacturer_database[trinket.get_public_key()] = true;
    manufacturer_database[car.get_public_key()] = true;

    cout << "(registration)\t"
         << trinket.get_public_key() << " (public key written to trinket),\t"
         << car.get_public_key() << " (public key written to car)" << endl;

    DSA_SIG* signed_data = trinket.sign_data(Command::COMMAND_OPEN_DOOR);
    cout << "(signing command \"OPEN DOOR\") trinket->car " << signed_data << endl;

    cout << "(verifying signature) car->trinket " << signed_data << endl;
    bool is_verified_data = car.verify_signature(signed_data, Command::COMMAND_OPEN_DOOR, trinket.get_dsa(), manufacturer_database);

    if (is_verified_data) {
        cout << "(action) car: check response - ok, OPEN DOOR" << endl;
    }

    delete signed_data;
    return EXIT_SUCCESS;
}
