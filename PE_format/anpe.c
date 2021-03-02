#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include<string.h>

/*
  anpe v1.0
  Program to analyze PE files ( Portable Executable ) 
 

  STATUS CODES:
  1  -  File doesn't exist
  2  -  File isn't a PE

*/

int exception(int8_t *, int8_t);
int check_PE(int8_t *);

int main(){
  int8_t program_status = 0;

  // Checking if the file is an PE
  program_status = check_PE("EasyPass.exe");
  if ( program_status != 0)
    return program_status
  

  FILE *PE_file;
  PE_file = fopen("EasyPass.exe", "rb");
  
  // Checking file existence
  if ( PE_file == NULL ){
    program_status = exception(" File doesn't exist ", 1);
    if ( program_status != 0 )
      return program_status;
  }

  // Checking MZ DOS HEADER
  unsigned char *buffer;
  buffer = malloc(2);
  fread(buffer, sizeof *buffer, 2, PE_file);
  fseek(PE_file, 0, SEEK_SET);
  // sizeof *buffer == 8 i don't know why.
  
  if ( strcmp(buffer, "MZ") != 0){
    program_status = exception(" Not a PE file ", 2);
    if ( program_status != 0 )
      return program_status;
  }else{
    printf("[1] HEADER: %s ( Mark Zbikowsky )\n", buffer);
  }
  

  fclose(PE_file);  
  return 0;

}

int check_PE(int8_t * filename){
  unsigned char *buffer;
  buffer = malloc(2);
  FILE *fptr;
  fptr = fopen(filename, "rb");
  fread(buffer, sizeof *buffer, 2, fptr);
  fclose(fptr);

  if ( strcmp(buffer, "MZ") != 0)
    return exception(" Not a PE file ", 2);

  return 0;
}

int exception(int8_t * reason, int8_t return_code){
  puts("[X] ERROR...");
  printf("[!] Reason: %s\n", reason);  
  printf("[!] Return code %d\n", return_code);
  return return_code;
}

    
