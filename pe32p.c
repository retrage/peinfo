#include "pe32p.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

static void load_file(char *head)
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
    }

    nthdr = (IMAGE_NT_HEADERS *)(head + doshdr->e_lfanew);
    if (nthdr->Signature != MAGIC_PE) {
        fprintf(stderr, "This file is not supported.\n");
    }

    fhdr = &nthdr->FileHeader;
    fprintf(stdout, "Machine:\t\t\t0x%04x\n", fhdr->Machine);
    fprintf(stdout, "Number of Section:\t\t%d\n", fhdr->NumberOfSections);
    fprintf(stdout, "Time Stamp:\t\t\t%d\n", fhdr->TimeDateStamp);
    fprintf(stdout, "Size of Optional Header:\t0x%04x\n",
                                        fhdr->SizeOfOptionalHeader);

    if (fhdr->Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
        fprintf(stdout, "Relocation info stripped.\n");
    }

    if (!(fhdr->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
        fprintf(stderr, "The file must be executable.\n");
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


    if (fhdr->Characteristics & IMAGE_FILE_32BIT_MACHINE) {
    } else {
    }

    opthdr = &nthdr->OptionalHeader;
    switch(opthdr->Magic) {
        case 0x10b:
            fprintf(stdout, "PE32\n");
            break;
        case 0x20b:
            fprintf(stdout, "PE+\n");
            break;
        case 0x107:
            fprintf(stdout, "ROM\n");
            break;
        default:
            fprintf(stderr, "Magic not matched\n");
            exit(1);
            break;
    }

    fprintf(stdout, "SizeOfCode: %x\n",
                        opthdr->SizeOfCode);

    fprintf(stdout, "AddressOfEntryPoint: %x\n",
                        opthdr->AddressOfEntryPoint);

    fprintf(stdout, "BaseOfCode: %x\n",
                        opthdr->BaseOfCode);

    fprintf(stdout, "ImageBase: %lx\n",
                        opthdr->ImageBase);

    fprintf(stdout, "SectionAlignment:\t\t0x%08x\n",
                        opthdr->SectionAlignment);

    fprintf(stdout, "FileAlignment:\t\t\t0x%08x\n",
                        opthdr->FileAlignment);

    fprintf(stdout, "SizeOfImage:\t\t\t0x%08x\n",
                        opthdr->SizeOfImage);

    fprintf(stdout, "SizeOfHeaders:\t\t\t0x%08x\n",
                        opthdr->SizeOfHeaders);

    for (i = 0; i < opthdr->NumberOfRvaAndSizes; i++) {
      fprintf(stdout, "DataDirectory %d\n", i);
      IMAGE_DATA_DIRECTORY *datadir = &opthdr->DataDirectory[i];
      fprintf(stdout, "\tVirtualAddress: %x\n", datadir->VirtualAddress);
      fprintf(stdout, "\tSize: %x\n", datadir->Size);
    }

    for (i=0; i<fhdr->NumberOfSections; i++) {
        fprintf(stdout, "Section %d\n", i);
        sechdr = (IMAGE_SECTION_HEADER *)
            ((char *)nthdr + sizeof(IMAGE_NT_HEADERS)
             + sizeof(IMAGE_DATA_DIRECTORY) * opthdr->NumberOfRvaAndSizes
             + sizeof(IMAGE_SECTION_HEADER) * i);
        fprintf(stdout, "\tName: %s\n",
                                sechdr->Name);
        fprintf(stdout, "\tVirtualSize:\t\t0x%08x\n",
                                sechdr->Misc.VirtualSize);
        fprintf(stdout, "\tVirtualAddress:\t\t0x%08x\n",
                                sechdr->VirtualAddress);
        fprintf(stdout, "\tSizeOfRawData:\t\t0x%08x\n",
                                sechdr->SizeOfRawData);
        fprintf(stdout, "\tPointerToRawData:\t0x%08x\n",
                                sechdr->PointerToRawData);
        fprintf(stdout, "\tPointerToRelocations:\t0x%08x\n",
                                sechdr->PointerToRelocations);
        fprintf(stdout, "\tPointerToLinenumbers:\t0x%08x\n",
                                sechdr->PointerToLinenumbers);
        fprintf(stdout, "\tNumberOfRelocations:\t%d\n",
                                sechdr->NumberOfRelocations);
        fprintf(stdout, "\tNumberOfLinenumbers:\t%d\n",
                                sechdr->NumberOfLinenumbers);
        fprintf(stdout, "\tCharacteristics:");
        fprintf(stdout, "\t%x ", sechdr->Characteristics);

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
}

int main(int argc, char *argv[])
{
    int fd;
    struct stat sb;
    char *head;
    static char filename[128];

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
    load_file(head);

    close(fd);

    return  0;
}
