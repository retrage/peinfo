/* SPDX-License-Identifier: MIT */

#include "pe.h"
#include "peinfo.h"

static void print_fhdr(FILE *stream, IMAGE_FILE_HEADER *fhdr)
{
  if (!stream || !fhdr)
    return;

  print_kv(stream, "Machine", &fhdr->Machine, FMT_HEX2);
  print_kv(stream, "NumberOfSections", &fhdr->NumberOfSections, FMT_DEC2);
  print_kv(stream, "TimeDateStamp", &fhdr->TimeDateStamp, FMT_DEC4);
  print_kv(stream, "PointerToSymbolTable", &fhdr->PointerToSymbolTable, FMT_HEX4);
  print_kv(stream, "NumberOfSymbols", &fhdr->NumberOfSymbols, FMT_DEC4);
  print_kv(stream, "SizeOfOptionalHeader", &fhdr->SizeOfOptionalHeader, FMT_HEX2);
  print_kv(stream, "Characteristics", &fhdr->Characteristics, FMT_HEX2);
}

static void print_opthdr_std(FILE *stream, OPT_HDR_STD *opthdr_std)
{
  if (!stream || !opthdr_std)
    return;

  print_kv(stream, "Magic", &opthdr_std->Magic, FMT_HEX2);
  print_kv(stream, "MajorLinkerVersion", &opthdr_std->MajorLinkerVersion, FMT_DEC1);
  print_kv(stream, "MinorLinkerVersion", &opthdr_std->MinorLinkerVersion, FMT_DEC1);
  print_kv(stream, "SizeOfCode", &opthdr_std->SizeOfCode, FMT_HEX4);
  print_kv(stream, "SizeOfInitializedData", &opthdr_std->SizeOfInitializedData, FMT_HEX4);
  print_kv(stream, "SizeOfUnnitializedData", &opthdr_std->SizeOfUninitializedData, FMT_HEX4);
  print_kv(stream, "AddressOfEntryPoint", &opthdr_std->AddressOfEntryPoint, FMT_HEX4);
  print_kv(stream, "BaseOfCode", &opthdr_std->BaseOfCode, FMT_HEX4);
  if (opthdr_std->Magic == MAGIC_PE32)
    print_kv(stream, "BaseOfData", &opthdr_std->BaseOfData, FMT_HEX4);
}

static void print_datadir(FILE *stream, IMAGE_DATA_DIRECTORY *dir)
{
  if (!stream || !dir)
    return;

  print_kv(stream, "VirtualAddress", &dir->VirtualAddress, FMT_HEX4);
  print_kv(stream, "Size", &dir->Size, FMT_HEX4);
}

static void print_datadirs(FILE *stream, IMAGE_DATA_DIRECTORY dir[], int ndirs)
{
  if (!stream || !dir)
    return;

  for (int i = 0; i < ndirs; i++)
    print_datadir(stream, &dir[i]);
}

static void print_pe32_opthdr(FILE *stream, IMAGE_PE32_OPTIONAL_HEADER *opthdr)
{
  if (!stream || !opthdr)
    return;

  print_opthdr_std(stream, (OPT_HDR_STD *)opthdr);

  print_kv(stream, "ImageBase", &opthdr->ImageBase, FMT_HEX4);
  print_kv(stream, "SectionAlignment", &opthdr->SectionAlignment, FMT_HEX4);
  print_kv(stream, "FileAlignment", &opthdr->FileAlignment, FMT_HEX4);
  /* TODO: more fields to be printed */
  print_kv(stream, "SizeOfImage", &opthdr->SizeOfImage, FMT_HEX4);
  print_kv(stream, "SizeOfHeaders", &opthdr->SizeOfHeaders, FMT_HEX4);

  print_datadirs(stream, opthdr->DataDirectory, opthdr->NumberOfRvaAndSizes);
}

static void print_pe32p_opthdr(FILE *stream, IMAGE_PE32P_OPTIONAL_HEADER *opthdr)
{
  if (!stream || !opthdr)
    return;

  print_opthdr_std(stream, (OPT_HDR_STD *)opthdr);

  print_kv(stream, "ImageBase", &opthdr->ImageBase, FMT_HEX8);
  print_kv(stream, "SectionAlignment", &opthdr->SectionAlignment, FMT_HEX4);
  print_kv(stream, "FileAlignment", &opthdr->FileAlignment, FMT_HEX4);
  /* TODO: more fields to be printed */
  print_kv(stream, "SizeOfImage", &opthdr->SizeOfImage, FMT_HEX4);
  print_kv(stream, "SizeOfHeaders", &opthdr->SizeOfHeaders, FMT_HEX4);

  print_datadirs(stream, opthdr->DataDirectory, opthdr->NumberOfRvaAndSizes);
}

static void print_sechdr(FILE *stream, IMAGE_SECTION_HEADER *sechdr)
{
  if (!stream || !sechdr)
    return;

  print_kv(stream, "Name", &sechdr->Name, FMT_STR);
  print_kv(stream, "VirtualSize", &sechdr->Misc.VirtualSize, FMT_HEX4);
  print_kv(stream, "VirtualAddress", &sechdr->VirtualAddress, FMT_HEX4);
  print_kv(stream, "SizeOfRawData", &sechdr->SizeOfRawData, FMT_HEX4);
  print_kv(stream, "PointerToRawData", &sechdr->PointerToRawData, FMT_HEX4);
  print_kv(stream, "PointerToRelocations", &sechdr->PointerToRelocations, FMT_HEX4);
  print_kv(stream, "PointerToLinenumbers", &sechdr->PointerToLinenumbers, FMT_HEX4);
  print_kv(stream, "NumberOfRelocations", &sechdr->NumberOfRelocations, FMT_HEX2);
  print_kv(stream, "NumberOfLinenumbers", &sechdr->NumberOfLinenumbers, FMT_HEX2);
  print_kv(stream, "Characteristics", &sechdr->Characteristics, FMT_HEX4);
}

static void *parse_pe32_opthdr(void *buf)
{
  if (!buf)
    return NULL;

  IMAGE_PE32_OPTIONAL_HEADER *opthdr = (IMAGE_PE32_OPTIONAL_HEADER *)buf;

  if (opthdr->Magic != MAGIC_PE32)
    return NULL;

  print_pe32_opthdr(stdout, opthdr);

  return buf + sizeof(IMAGE_PE32_OPTIONAL_HEADER) + sizeof(IMAGE_DATA_DIRECTORY) * opthdr->NumberOfRvaAndSizes;
}

static void *parse_pe32p_opthdr(void *buf)
{
  if (!buf)
    return NULL;

  IMAGE_PE32P_OPTIONAL_HEADER *opthdr = (IMAGE_PE32P_OPTIONAL_HEADER *)buf;

  if (opthdr->Magic != MAGIC_PE32P)
    return NULL;

  print_pe32p_opthdr(stdout, opthdr);

  return buf + sizeof(IMAGE_PE32P_OPTIONAL_HEADER) + sizeof(IMAGE_DATA_DIRECTORY) * opthdr->NumberOfRvaAndSizes;
}

static void parse_sechdrs(void *buf, int nsec)
{
  if (!buf)
    return;

  for (int i = 0; i < nsec; i++) {
    IMAGE_SECTION_HEADER *sechdr = (IMAGE_SECTION_HEADER *)(buf + sizeof(IMAGE_SECTION_HEADER) * i);
    print_sechdr(stdout, sechdr);
  }
}

static int parse_pehdr(void *buf)
{
  IMAGE_DOS_HEADER *doshdr;
  IMAGE_NT_HEADERS *nthdrs;
  IMAGE_FILE_HEADER *fhdr;
  void *opthdr;
  void *sechdr;

  if (!buf) {
    fprintf(stderr, "Invalid input\n");
    return 1;
  }

  doshdr = (IMAGE_DOS_HEADER *)buf;
  if (doshdr->e_magic != MAGIC_MZ) {
    fprintf(stderr, "Unsupported file format\n");
    return 1;
  }

  nthdrs = (IMAGE_NT_HEADERS *)(buf + doshdr->e_lfanew);
  if (nthdrs->Signature != MAGIC_PE) {
    fprintf(stderr, "Unsupported file format\n");
    return 1;
  }

  fhdr = &nthdrs->FileHeader;
  print_fhdr(stdout, fhdr);

  opthdr = (void *)nthdrs + sizeof(IMAGE_NT_HEADERS);

  sechdr = parse_pe32_opthdr(opthdr);
  if (sechdr)
    parse_sechdrs(sechdr, fhdr->NumberOfSections);
  sechdr = parse_pe32p_opthdr(opthdr);
  if (sechdr)
    parse_sechdrs(sechdr, fhdr->NumberOfSections);

  return 0;
}

void usage(const char *argv0)
{
  fprintf(stderr, "Usage: %s INPUT\n", argv0);
}

int main(int argc, char *argv[])
{
  int fd;
  struct stat sb;
  void *buf;
  int rc;

  if (argc < 2) {
    usage(argv[0]);
    return 1;
  }

  fd = open(argv[1], O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "Could not open file: %s\n", argv[1]);
    return 1;
  }

  fstat(fd, &sb);
  buf = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);

  close(fd);

  rc = parse_pehdr(buf);

  munmap(buf, sb.st_size);

  return rc;
}
