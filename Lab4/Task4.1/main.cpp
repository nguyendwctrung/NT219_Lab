#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;

#include <fstream>
using std::ifstream;
using std::istreambuf_iterator;
using std::ofstream;

#include <string>
using std::string;

#include <vector>
using std::vector;

#include <stdexcept>
using std::invalid_argument;
using std::runtime_error;

#include <random>
using std::random_device;
using std::mt19937;
using std::uniform_int_distribution;

#include <chrono>
using namespace std::chrono;

#include <exception>
using std::exception;

#include <thread>
using std::thread;

#include <mutex>
using std::mutex;
using std::lock_guard;

#include "cryptopp/sha.h"
using CryptoPP::SHA224;
using CryptoPP::SHA256;
using CryptoPP::SHA384;
using CryptoPP::SHA512;

#include "cryptopp/sha3.h"
using CryptoPP::SHA3_224;
using CryptoPP::SHA3_256;
using CryptoPP::SHA3_384;
using CryptoPP::SHA3_512;

#include "cryptopp/shake.h"
using CryptoPP::SHAKE128;
using CryptoPP::SHAKE256;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;

#include "cryptopp/filters.h"
using CryptoPP::HashFilter;
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include <iomanip>
using std::left;
using std::setw;
using std::fixed;
using std::setprecision;

#include <functional>
using std::ref;
using std::cref;

#include <numeric>

#ifdef _WIN32
#include <windows.h>
#elif defined(__linux__) || defined(__unix__)
#include <locale.h>
#endif

void HashFunction(const string& input, const string& hashType, int shakeDigestLength = 0) {
    string output;
    HexEncoder encoder(new StringSink(output));

    if (hashType == "SHA224") {
        SHA224 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    } else if (hashType == "SHA256") {
        SHA256 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    } else if (hashType == "SHA384") {
        SHA384 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    } else if (hashType == "SHA512") {
        SHA512 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));    
    } else if (hashType == "SHA3-224") {
        SHA3_224 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    } else if (hashType == "SHA3-256") {
        SHA3_256 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    } else if (hashType == "SHA3-384") {
        SHA3_384 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    } else if (hashType == "SHA3-512") {
        SHA3_512 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    } else if (hashType == "SHAKE128") {
        SHAKE128 hash(shakeDigestLength);
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    } else if (hashType == "SHAKE256") {
        SHAKE256 hash(shakeDigestLength);
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    } else {
        cerr << "Invalid hash type!" << endl;
        return;
    }
    cout << "Digest (" << hashType << "): " << output << endl;
}

void HashFunctionTest(const string& input, const string& hashType, int shakeDigestLength = 0) {
    string output;
    HexEncoder encoder(new StringSink(output));

    if (hashType == "SHA224") {
        SHA224 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    } else if (hashType == "SHA256") {
        SHA256 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    } else if (hashType == "SHA384") {
        SHA384 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    } else if (hashType == "SHA512") {
        SHA512 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));    
    } else if (hashType == "SHA3-224") {
        SHA3_224 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    } else if (hashType == "SHA3-256") {
        SHA3_256 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    } else if (hashType == "SHA3-384") {
        SHA3_384 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    } else if (hashType == "SHA3-512") {
        SHA3_512 hash;
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    } else if (hashType == "SHAKE128") {
        SHAKE128 hash(shakeDigestLength);
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    } else if (hashType == "SHAKE256") {
        SHAKE256 hash(shakeDigestLength);
        StringSource(input, true, new HashFilter(hash, new Redirector(encoder)));
    } else {
        cerr << "Invalid hash type!" << endl;
        return;
    }
}

string ReadFromFile(const string& fileName) {
    ifstream file(fileName, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        cerr << "Failed to open file: " << fileName << endl;
        exit(EXIT_FAILURE);
    }
    size_t size = file.tellg();
    if (size > 1024 * 1024 * 100) { // Limit to 100MB
        cerr << "File too large: " << fileName << endl;
        exit(EXIT_FAILURE);
    }
    file.seekg(0, std::ios::beg);
    return string((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
}

float CalculateAverage(const vector<float>& vec) {
    if (vec.empty()) {
        throw invalid_argument("The vector is empty");
    }
    double sum = std::accumulate(vec.begin(), vec.end(), 0.0);
    return sum / vec.size();
}

string GenerateRandomString(size_t length) {
    const string characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    random_device rd;
    mt19937 generator(rd());
    uniform_int_distribution<> distribution(0, characters.size() - 1);

    string randomString;
    randomString.reserve(length);
    for (size_t i = 0; i < length; i++) {
        randomString += characters[distribution(generator)];
    }
    return randomString;
}

void RunHashFunction(const string& input, const string& hashType, int shakeDigestLength, 
                     double& resultTime, mutex& mtx, const int nums_run) {
    vector<float> hash_times;

    for (int i = 0; i < nums_run; i++) {
        auto start = high_resolution_clock::now();
        if (hashType == "SHAKE128" || hashType == "SHAKE256") {
            HashFunctionTest(input, hashType, shakeDigestLength);
        } else {
            HashFunctionTest(input, hashType);
        }
        auto end = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(end - start);
        hash_times.push_back(duration.count() / 1000.0f);
    }

    float avg_time = CalculateAverage(hash_times);
    lock_guard<mutex> lock(mtx);
    resultTime = avg_time;
}

void PerformanceTest() {
    try {
        string type[10] = {"SHA224", "SHA256", "SHA384", "SHA512", "SHA3-224", 
                           "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256"};
        vector<size_t> inputSizes = {1024, 10 * 1024, 100 * 1024, 500 * 1024, 1024 * 1024, 5 * 1024 * 1024};
        vector<string> randomStrings;
        const int nums_run = 100;

        string osName;
#ifdef _WIN32
        osName = "Windows";
#else
        osName = "Linux";
#endif

        ofstream outfile("performance_results.txt", std::ios::app);
        if (!outfile.is_open()) {
            throw runtime_error("Unable to open performance_results.txt");
        }

        cout << left << setw(15) << "Input Size (KB)"<< setw(15) << "OS";
        for (const auto& hashType : type) {
            cout << setw(10) << hashType;
        }
        cout << endl;
        cout << string(15 + 15 + 10 * 10, '-') << endl;
        
        outfile << left << setw(15) << "Input Size (KB)" << setw(15) << "OS";
        for (const auto& hashType : type) {
            outfile << setw(10) << hashType;
        }
        outfile << endl;
        outfile << string(15 + 15 + 10 * 10, '-') << endl;

        for (size_t size : inputSizes) {            
            randomStrings.push_back(GenerateRandomString(size));
        }

        mutex mtx;

        for (size_t s = 0; s < randomStrings.size(); s++) {
            double size_in_kb = inputSizes[s] / 1024.0;

            vector<double> avg_time(10, 0.0);
            vector<thread> threads;

            for (int i = 0; i < 10; i++) {
                threads.emplace_back(RunHashFunction, 
                                    cref(randomStrings[s]), 
                                    type[i], 
                                    32, 
                                    ref(avg_time[i]), 
                                    ref(mtx), 
                                    nums_run);
            }

            for (auto& t : threads) {
                t.join();
            }
            
            cout << fixed << setprecision(2);
            cout << left << setw(15) << size_in_kb << setw(15) << osName;
            for (double time : avg_time) {
                cout << setw(10) << time;
            }               
            cout << endl;

            outfile << fixed << setprecision(2);
            outfile << left << setw(15) << size_in_kb << setw(15) << osName;
            for (double time : avg_time) {
                outfile << setw(10) << time;
            }                      
            outfile << endl;
        }
        outfile.close();
    }
    catch (const exception& e) {
        cerr << "Error during performance test: " << e.what() << endl;
    }
}

int main() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#else
    setlocale(LC_ALL, "en_US.UTF-8");
#endif

    int choice;
    string input;
    string fileName;
    int shakeDigestLength = 0;

    cout << "Choose input method:\n1. Input from screen\n2. Input from file\n3. Test performance\nMethod: ";
    if (!(cin >> choice)) {
        cerr << "Invalid input! Please enter a number." << endl;
        return EXIT_FAILURE;
    }
    cin.ignore();

    switch(choice) {
        case 1:
            cout << "Enter the plaintext: ";
            getline(cin, input);
            break;
        case 2:
            cout << "Enter the file name: ";
            cin >> fileName;
            input = ReadFromFile(fileName);
            break;
        case 3:
            PerformanceTest();
            return 0;
        default:
            cerr << "Invalid method!" << endl;
            return EXIT_FAILURE;
    }

    cout << "Choose hash type:\n1. SHA224\n2. SHA256\n3. SHA384\n4. SHA512\n5. SHA3-224\n6. SHA3-256\n7. SHA3-384\n8. SHA3-512\n9. SHAKE128\n10. SHAKE256\nChoice: ";
    if (!(cin >> choice)) {
        cerr << "Invalid input! Please enter a number." << endl;
        return EXIT_FAILURE;
    }

    string hashType;
    switch(choice) {
        case 1:
            hashType = "SHA224";
            break;
        case 2:
            hashType = "SHA256";
            break;
        case 3:
            hashType = "SHA384";
            break;
        case 4:
            hashType = "SHA512";
            break;
        case 5:
            hashType = "SHA3-224";
            break;
        case 6:
            hashType = "SHA3-256";
            break;
        case 7:
            hashType = "SHA3-384";
            break;
        case 8:
            hashType = "SHA3-512";
            break;
        case 9:
            hashType = "SHAKE128";
            cout << "Enter digest output length for SHAKE128: ";
            if (!(cin >> shakeDigestLength) || shakeDigestLength <= 0) {
                cerr << "Invalid digest length! Must be a positive number." << endl;
                return EXIT_FAILURE;
            }
            break;
        case 10:
            hashType = "SHAKE256";
            cout << "Enter digest output length for SHAKE256: ";
            if (!(cin >> shakeDigestLength) || shakeDigestLength <= 0) {
                cerr << "Invalid digest length! Must be a positive number." << endl;
                return EXIT_FAILURE;
            }
            break;
        default:
            cerr << "Invalid type!" << endl;
            return EXIT_FAILURE;
    }

    HashFunction(input, hashType, shakeDigestLength);
    return 0;
}