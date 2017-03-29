#include "pe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

static void* load_file(char *head)
{
    int i;
    IMAGE_DOS_HEADER *doshdr;
    IMAGE_NT_HEADERS *nthdr;
    IMAGE_FILE_HEADER *fhdr;
    IMAGE_OPTIONAL_HEADER *opthdr;
    IMAGE_SECTION_HEADER *sechdr;

    doshdr = (IMAGE_DOS_HEADER *)head;
    if (doshdr->e_magic != MAGIC_MZ) {
        fprintf(stderr, "This file is not supported.\n");
        return NULL;
    }

    nthdr = (IMAGE_NT_HEADERS *)(head + doshdr->e_lfanew);
    if (nthdr->Signature != MAGIC_PE) {
        fprintf(stderr, "This file is not supported.\n");
        return NULL;
    }

    fhdr = &nthdr->FileHeader;
    fprintf(stdout, "Machine: %x\n", fhdr->Machine);
    fprintf(stdout, "Number of Section: %d\n", fhdr->NumberOfSections);
    fprintf(stdout, "Time Stamp: %d\n", fhdr->TimeDateStamp);
    fprintf(stdout, "Size of Optional Header: %d\n",
                                        fhdr->SizeOfOptionalHeader);

    if (fhdr->Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
        fprintf(stdout, "Relocation info stripped.\n");
    }

    if (!(fhdr->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
        fprintf(stderr, "The file must be executable.\n");
        return NULL;
    }
    
    if (fhdr->Characteristics & IMAGE_FILE_32BIT_MACHINE) {
        fprintf(stdout, "32-bit Architecture\n");
    }

    if (fhdr->Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) {
        fprintf(stdout, "Removable Run from swap.\n");
    }

    if (fhdr->Characteristics & IMAGE_FILE_SYSTEM) {
        fprintf(stdout, "This file is a system file.\n");
    }

    if (fhdr->Characteristics & IMAGE_FILE_DLL) {
        fprintf(stdout, "This file is DLL.\n");
    }


    opthdr = &nthdr->OptionalHeader;
    if (opthdr->Magic != 0x20b) {
        fprintf(stderr, "This format is not supported. Magic: %x\n",
                                                            opthdr->Magic);
        exit(1);
    }

    fprintf(stdout, "AddressOfEntryPoint: %x\n",
                        opthdr->AddressOfEntryPoint);

    for (i=0; i<fhdr->NumberOfSections; i++) {
        fprintf(stdout, "Section %d\n", i);
        sechdr = (IMAGE_SECTION_HEADER *)
            (head + doshdr->e_lfanew + 
                sizeof(IMAGE_NT_HEADERS)+ sizeof(IMAGE_SECTION_HEADER)*i);
        fprintf(stdout, "\tName: %s\n",
                                sechdr->Name);
        fprintf(stdout, "\tVirtualSize: %x\n",
                                sechdr->Misc.VirtualSize);
        fprintf(stdout, "\tSizeOfRawData: %x\n",
                                sechdr->SizeOfRawData);
        fprintf(stdout, "\tPointerToRawData: %x\n",
                                sechdr->PointerToRawData);
        fprintf(stdout, "\tPointerToRelocations: %x\n",
                                sechdr->PointerToRelocations);
        fprintf(stdout, "\tPointerToLinenumbers: %x\n",
                                sechdr->PointerToLinenumbers);
        fprintf(stdout, "\tNumberOfRelocations: %d\n",
                                sechdr->NumberOfRelocations);
        fprintf(stdout, "\tNumberOfLinenumbers: %d\n",
                                sechdr->NumberOfLinenumbers);
        fprintf(stdout, "\tCharacteristics:");
        fprintf(stdout, " %x ", sechdr->Characteristics);

        if (sechdr->Characteristics & IMAGE_SCN_MEM_READ) {
            fprintf(stdout, "r");
        } else {
            fprintf(stdout, "-");
        }

        if (sechdr->Characteristics & IMAGE_SCN_MEM_WRITE) {
            fprintf(stdout, "w");
        } else {
            fprintf(stdout, "-");
        }

        if (sechdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            fprintf(stdout, "x");
        } else {
            fprintf(stdout, "-");
        }
        
        if (sechdr->Characteristics & IMAGE_SCN_CNT_CODE) {
            fprintf(stdout, " exec");
        }
        if (sechdr->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
            fprintf(stdout, " inited");
        }
        if (sechdr->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
            fprintf(stdout, " uninited");
        }
        fprintf(stdout, "\n");

    }

    return (void *)1;
}

int main(int argc, char *argv[])
{
    int fd;
    struct stat sb;
    char *head;
    static char filename[128];
    int f;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s input\n", argv[0]);
        exit(1);
    }

    strcpy(filename, argv[1]);
    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Could not open file: %s\n", filename);
        exit(1);
    }
    fstat(fd, &sb);
    head = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
    f = load_file(head);
    if (f == NULL) {
        fprintf(stderr, "Could not load file: %s\n", filename);
        exit(1);
    }

    close(fd);

    return  0;
}
