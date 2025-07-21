/*
dcanalyzer.c - https://pastebin.com/DEkWGR6E
--
Analyzer for DarkComet Servers, make sure the server is fully unpacked before 
using this tool. It will decrypt all known data, if it doesn't work you may be 
working with a very old version of darkcomet and you should have a look at 
the PE resources for the unencrypted data. 

This tool is public domain. Tested under GCC and VS2010 with many darkcomet 
versions. 
*/
#define _BSD_SOURCE /* make gcc happy with snprintf as ansi */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef WIN32
#include <Windows.h>
#endif

#if _MSC_VER
#define snprintf _snprintf /* work around for microsoft's "C" compiler */
#endif

/* We search the entire file for this string to find the RC4 key */
#define KEY_PREFIX "#KCMDDC" 


int process(char * file);
void ShowOutput(char * str);
void process_resource_table(int pos, char found, char * goal); 

FILE * fh;
int32_t rsrc_pos;
int32_t rsrc_virtual;
char * dcstr = NULL;

/* RC4 borrowed from FreeBSD */
struct rc4_state {
	uint8_t	perm[256];
	uint8_t	index1;
	uint8_t	index2;
};

static __inline void swap_bytes(uint8_t *a, uint8_t *b)
{
	uint8_t temp;
	temp = *a;
	*a = *b;
	*b = temp;
}

void rc4_init(struct rc4_state * state, uint8_t *key, int keylen)
{
	uint8_t j;
	int i;

	/* Initialize state with identity permutation */
	for (i = 0; i < 256; i++)
		state->perm[i] = (uint8_t)i; 
	state->index1 = 0;
	state->index2 = 0;
  
	/* Randomize the permutation using key data */
	for (j = i = 0; i < 256; i++) {
		j += state->perm[i] + key[i % keylen]; 
		swap_bytes(&state->perm[i], &state->perm[j]);
	}
}

void rc4_crypt(struct rc4_state * state, uint8_t *inbuf, uint8_t *outbuf, 
	int buflen)
{
	int i;
	uint8_t j;

	for (i = 0; i < buflen; i++) {

		/* Update modification indicies */
		state->index1++;
		state->index2 += state->perm[state->index1];

		/* Modify permutation */
		swap_bytes(&state->perm[state->index1],
		    &state->perm[state->index2]);

		/* Encrypt/decrypt next byte */
		j = state->perm[state->index1] + state->perm[state->index2];
		outbuf[i] = inbuf[i] ^ state->perm[j];
	}
}
/* end FreeBSD RC4 code */

/* my PE header structs */
struct DATA_DIR 
{
	uint32_t addr;
	uint32_t size;
};

struct RES_DIR_TABLE 
{
	uint32_t characteristics;
	uint32_t timestamp;
	uint16_t major;
	uint16_t minor;
	uint16_t num_name_elems;
	uint16_t num_id_elems;
};

struct RES_DIR_ENTRY 
{
	union 
	{
		uint32_t name_rva;
		uint32_t id;
	} identifier; 
	union 
	{
		uint32_t data_entry_rva;
		uint32_t subdir_rva;
	} child;
};

struct RES_DATA 
{
	uint32_t data_rva;
	uint32_t size;
	uint32_t codepage;
	uint32_t reserved;
};



void process_resource_entry(struct RES_DIR_ENTRY entry, char found, 
	char * goal)
{
	struct RES_DATA data;
	
	if (entry.child.data_entry_rva & 0x80000000) {
		/* process subdir entry */
		process_resource_table(entry.child.subdir_rva & 0x7FFFFFFF, 
			found, goal);
	} else {
		if (found) {
			fseek(fh, rsrc_pos + entry.child.data_entry_rva, 
				SEEK_SET);
			fread(&data, sizeof(data), 1, fh);
			dcstr = (char*) malloc(data.size+1);
			dcstr[data.size] = '\0';
			fseek(fh, data.data_rva - rsrc_virtual + rsrc_pos, 
				SEEK_SET);
			fread(dcstr, 1, data.size, fh);
		}
		/* process data entry */
	}
}

void process_resource_entry_id(struct RES_DIR_ENTRY entry, char found, 
	char * goal) 
{
	process_resource_entry(entry, found, goal);
}

char check_unicode_str(char * goal, char * input, unsigned int len) 
{
	unsigned int i;
	char next;
	if (strlen(goal) == len) {
		for (i = 0; i < len*2; i++) {
			next = (i % 2) == 0 ? goal[i/2] : 0;
			if (input[i] != next)
				return 0;
		}
	} else {
		return 0;
	}
	return 1;
}

void process_resource_entry_name(struct RES_DIR_ENTRY entry, char found, 
	char * goal) 
{
	uint16_t name_len;
	char * name;

	fseek(fh, rsrc_pos + (entry.identifier.name_rva & 0x7FFFFFFF), SEEK_SET);
	fread(&name_len, sizeof(name_len), 1, fh);

	name = (char*) malloc(name_len*2 + 1); 
	fread(name, 1, name_len*2, fh);

	if (check_unicode_str(goal, name, name_len)) {
		process_resource_entry(entry, 1, goal);
	} else {
		process_resource_entry(entry, found, goal);
	}	
}

void process_resource_table(int pos, char found, char * goal) 
{
	struct RES_DIR_TABLE table;
	int i;
	int length;
	struct RES_DIR_ENTRY * entries;

	fseek(fh, rsrc_pos + pos, SEEK_SET);
	fread(&table, sizeof(table), 1, fh);
	length = sizeof(struct RES_DIR_ENTRY) * 
		(table.num_id_elems + table.num_name_elems);
	entries = (struct RES_DIR_ENTRY*) malloc(length);
	fread(entries, length, 1, fh);

	for (i = 0; i < table.num_name_elems; i++) {
		process_resource_entry_name(entries[i], found, goal);
	}

	for (i = 0; i < table.num_id_elems; i++) {
		process_resource_entry_id(entries[i], found, goal);
	}
}

char * decrypt_dcdata(char * instr, char * key) 
{
	struct rc4_state rc4state;
	int i;
	int len = strlen(instr)/2;
	char * data;
	unsigned int tempdata;
	data = (char *)malloc(len);
	
	for (i = 0; i < len; i++) {
		sscanf(instr+(i*2), "%2X", &tempdata);
		data[i] = (char) tempdata;
	}
	rc4_init(&rc4state, (uint8_t*)key, strlen(key));
	rc4_crypt(&rc4state, (uint8_t*)data, (uint8_t*)data, len);
	data[len] = '\0';
	return data;
}

int main(int argc, char** argv) {

	if (argc < 2) {
		ShowOutput("Please specify a file!");
		return EXIT_FAILURE;
	}

	return process(argv[1]);
}

#ifdef WIN32
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
	LPSTR lpCmdLine, int nCmdShow) 
{
	char buffer[8192];
	OPENFILENAME ofn;
	if (__argc > 1) {
		return main(__argc, __argv);
	} else {
		ZeroMemory( &ofn , sizeof( ofn));
		ofn.lStructSize = sizeof(ofn);
		ofn.lpstrFile = buffer;
		ofn.lpstrFile[0] = '\0';
		ofn.nMaxFile = sizeof(buffer);
		ofn.lpstrFilter = "DarkComet Server Executables\0*.exe";
		ofn.nFilterIndex = 1;
		ofn.lpstrFileTitle = NULL;
		ofn.nMaxFileTitle = 0;
		ofn.lpstrInitialDir = NULL;
		ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
		GetOpenFileName(&ofn);

		return process(ofn.lpstrFile);
	}
}
#endif

void ShowOutput(char * str) 
{
#ifdef WIN32
		MessageBoxExA(NULL, str, "DCAnalyzer", 0, 0);
#else
		printf("%s\n", str);
#endif
}

/* simple scanner to parse key out of executable */
char * find_key_by_force() 
{
	int pos = 0;
	char * prefix = KEY_PREFIX;
	int max = strlen(prefix);
	char * keybuf = (char*) malloc(4096);
	char cur;
	fseek(fh, 0, SEEK_SET); /* go to start of file */
	
	do {
		fread(&cur, 1, 1, fh);
		
		if (pos >= max) {
			keybuf[pos] = cur;
			if (cur == '\0')
				break;
			pos++;
		} else if (cur == prefix[pos]) {
			keybuf[pos] = cur;
			pos++;
		} else {
			pos = 0;
		}

		if (pos == 4096) /* no heap overflow for you! */
			break;
	} while (!feof(fh));

	strncat(keybuf, "890", 4096); /* comes from a separate function */

	return keybuf;
}

int process(char * file) 
{
	uint16_t mz_hdr;
	uint32_t pe_hdr_loc; 
	uint32_t pe_hdr; 
	uint16_t opt_hdr; 
	uint32_t num_rva_sizes;
	uint32_t image_base;
	unsigned int opt_hdr_pos;
	unsigned int i;
	char * output;
	char buffer[1024];
	char final_buffer[8192];
	char section_name[9];
	char found;
	int successful;
	char * key;
    /* We search for these when we can't find the new DCDATA resource.
       Used for old versions of DarkComet */
	char * fallbacks[] = {"FWB", "GENCODE", "MUTEX", "NETDATA", "OFFLINEK", 
		"SID", "FTPUPLOADK", "FTPHOST", "FTPUSER", "FTPPASS", "FTPPORT", 
		"FTPSIZE", "FTPROOT", "PWD"};

	fh = fopen(file, "rb");
	if (fh == NULL) {
		ShowOutput("File open failed");
		return EXIT_FAILURE;
	}

	key = find_key_by_force();

	fseek(fh, 0, SEEK_SET); /* go to start of file */

	section_name[8] = '\0';

	fread(&mz_hdr, sizeof(int16_t), 1, fh); /* read first 2 bytes of file */
	if (mz_hdr != *(uint16_t*)"MZ") { 
		ShowOutput("Not an MZ Executable!");
		return EXIT_FAILURE;
	}

	fseek(fh, 0x3C, SEEK_SET);
	fread(&pe_hdr_loc, sizeof(pe_hdr_loc), 1, fh); /* offset of PE header */
	
	fseek(fh, pe_hdr_loc, SEEK_SET);
	fread(&pe_hdr, sizeof(pe_hdr), 1, fh); 

	if (pe_hdr != *(uint32_t*)"PE\0\0") {
		ShowOutput("Not a PE Executable!");
		return EXIT_FAILURE;
	}

	opt_hdr_pos = pe_hdr_loc + 0x18;
	fseek(fh, opt_hdr_pos, SEEK_SET);
	fread(&opt_hdr, sizeof(opt_hdr), 1, fh);

	if (opt_hdr != 0x010B) {
		ShowOutput("Invalid optional header!");
		return EXIT_FAILURE;
	}

	fseek(fh, opt_hdr_pos + 28, SEEK_SET); /* ImageBase so we can subtract it later */
	fread(&image_base, sizeof(image_base), 1, fh);

	fseek(fh, opt_hdr_pos + 92, SEEK_SET); /*  NumberOfRvaAndSizes */
	fread(&num_rva_sizes, sizeof(num_rva_sizes), 1, fh);

	if (num_rva_sizes > 0x10)
		num_rva_sizes = 0x10; /* enforce this so dumb tricks cannot work */
	
	fseek(fh, num_rva_sizes*8, SEEK_CUR);
	
	/* we should now be at the section headers */
	found = 0;
	do {
		fread(section_name, 1, 8, fh);
		if (strncmp(".rsrc", section_name, 8) == 0) {
			fseek(fh, 4, SEEK_CUR);
			fread(&rsrc_virtual, 4, 1, fh);
			fseek(fh, 4, SEEK_CUR);
			fread(&rsrc_pos, 4, 1, fh);
			found++;
			fseek(fh, 16, SEEK_CUR);   /* skip rest of this section header. */
		} else  {
			fseek(fh, 40-8, SEEK_CUR); /* skip rest of this section header. */
		}
	} while (found != 1);

	process_resource_table(0,0, "DCDATA");

	if (dcstr != NULL) {
		ShowOutput(decrypt_dcdata(dcstr, key));
	} else {
		final_buffer[0] = '\0';
		successful = 0;
		for (i = 0; i < (sizeof(fallbacks)/sizeof(*fallbacks)); i++) {
			process_resource_table(0,0, fallbacks[i]);
			if (dcstr != NULL) {
				output = decrypt_dcdata(dcstr, key);
				if (final_buffer[0] == '\0')
					snprintf(buffer, 1024, "%s: %s", fallbacks[i], output);
				else 
					snprintf(buffer, 1024, "\n%s: %s", fallbacks[i], output);
				strncat(final_buffer, buffer, 8192);
				successful++;
				dcstr = NULL; /* null it every round */
			}
		}
		if (successful) 

			ShowOutput(final_buffer);
		else 
			ShowOutput("Could not find any DarkComet resource!\n");

	}
	
	return EXIT_SUCCESS;
}
