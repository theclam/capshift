

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "capshift.h"

#define SWVERSION "v0.1 alpha"
#define SWRELEASEDATE "January 2015"

// capshift (pCAP time SHIFT) shifts the timestamps in pcap files by the specified time
// delta value. 
// Written by Foeh Mannay
// Please refer to http://networkbodges.blogspot.com for more information about this tool.
// This software is released under the Modified BSD license.

params_t *parseParams(int argc, char *argv[]){
	// Returns a struct with various parameters or NULL if invalid
	unsigned int i = 1;
	char 	*timestring = NULL,
			*endptr = NULL;
	params_t *parameters = (params_t*)malloc(sizeof(params_t));
	if(parameters == NULL) return(NULL);

	// There must be 4 parameters
	if(argc != 7) return(NULL);

	// Set some defaults
	parameters->infile = NULL;
	parameters->outfile = NULL;

	// Look for the various flags, then store the corresponding value
	while(i < argc){
		if(strcmp(argv[i],"-r") == 0){
			parameters->infile = argv[++i];
			i++;
			continue;
		}
		if(strcmp(argv[i],"-w") == 0){
			parameters->outfile = argv[++i];
			i++;
			continue;
		}
		if(strcmp(argv[i],"-o") == 0){
			timestring = argv[++i];
			i++;
			continue;
		}
		// If we get any unrecognised parameters just fail
		return(NULL);
	}
	
	// If the input files still aren't set, bomb
	if((parameters->infile == NULL) || (parameters->outfile == NULL)) return(NULL);

	// Try to parse the time offset string
	if(timestring == NULL) return NULL;
	
	// If there is a + or - present, set the sign accordingly
	switch(timestring[0]){
		case '-':
			parameters->sign = SUBTRACT;
			timestring++;
			break;
		case '+':
			parameters->sign = ADD;
			timestring++;
			break;
	}
	
	// If there are non-numeric characters present, bail out
	if((timestring[0] < '0') || (timestring[0] > '9')) return(NULL);
	
	// Grab the seconds
	parameters->secs = strtol(timestring, &endptr, 10);
	// Look for a decimal point, if present then grab and scale out microseconds
	if(endptr[0] == '.'){
		timestring = endptr + 1;
		parameters->usecs = strtol(timestring, &endptr, 10);

		// scale the usecs field as appropriate for place value
		i = endptr - timestring;
		while(i < 6){
			parameters->usecs *= 10;
			i++;
		}
		while(i > 6){
			parameters->usecs /= 10;
			i--;
		}
	} else parameters->usecs = 0;
	
	if(endptr[0] != '\x00') return(NULL);

	return(parameters);
}

int parse_pcap(FILE *capfile, FILE *outfile, long sign, long secs, long usecs){
	char 				*memblock = NULL;
	guint32				caplen = 0;
	int					count = 0;
	pcaprec_hdr_t		*rechdr = NULL;
	
	if(sign == ADD) {
		printf("\nParsing capfile, attempting to shift forward by %ld.%ld seconds...\n", secs, usecs);
	} else {
		printf("\nParsing capfile, attempting to shift backward by %ld.%ld seconds...\n", secs, usecs);
	}
	
	// Start parsing the capture file:
	rewind(capfile);
	clearerr(capfile);
	memblock = (char*)malloc(sizeof(pcap_hdr_t));
	if(memblock == NULL){
		printf("Insufficient memory to load capture header.\n");
		return(0);
	}
	// Read the pcap header
	if(fread (memblock, 1, sizeof(pcap_hdr_t), capfile) != sizeof(pcap_hdr_t)){
		printf("Truncated capture file header - aborting.\n");
		if(memblock != NULL) free(memblock);
		return(0);
	}
	// Verify the magic number in the header indicates a pcap file
	if(((pcap_hdr_t*)memblock)->magic_number != 2712847316){
		printf("\nError!\nThis is not a valid pcap file. If it has been saved as pcap-ng\nconsider converting it to original pcap format with tshark or similar.\n");
		if(memblock != NULL) free(memblock); 
		return(0);
	}
	// Allocate memory for the PCAP record header
	rechdr = (pcaprec_hdr_t*)malloc(sizeof(pcaprec_hdr_t));
	if(rechdr == NULL){
		printf("Error: unable to allocate memory for pcap record header!\n");
		return(0);
	}
	// Clone the input file's header
	rewind(outfile);
	clearerr(outfile);
	if(fwrite(memblock, 1, sizeof(pcap_hdr_t), outfile) != sizeof(pcap_hdr_t)){
		printf("Error: unable to write pcap header to output file!\n");
		return(0);
	}

	// Read in each frame.
	while((!feof(capfile)) & (!ferror(capfile))) {
		free(memblock);
		// Get the packet record header and examine it for the packet size
		caplen = fread (rechdr, 1, sizeof(pcaprec_hdr_t), capfile);

		if(caplen != sizeof(pcaprec_hdr_t)){
			if(caplen > 0) printf("Error: Truncated pcap file reading record header, %u/%lu!\n", caplen, sizeof(pcaprec_hdr_t));
			break;
		}
				
		// Adjust timestamp as required, handling over/underflow
		rechdr->ts_sec += (sign * secs);
		if(sign == SUBTRACT){
			if (usecs > rechdr->ts_usec){
				rechdr->ts_sec--;
				rechdr->ts_usec += (1000000 - usecs);
			} else {
				rechdr->ts_usec -= usecs;
			} 
		} else {
			rechdr->ts_usec += usecs;
			if (rechdr->ts_usec > 1000000){
				rechdr->ts_sec++;
				rechdr->ts_usec -= 1000000;
			}
		}

		caplen = rechdr->incl_len;
		
		memblock = malloc(caplen);
		if(memblock == NULL){
			printf("Error: Could not allocate memory for pcap data!\n");
			return(count);
		}
		// Get the actual packet data and copy it verbatim
		if(fread (memblock, 1, caplen, capfile) != caplen){
			printf("Error: Truncated pcap file reading capture!\n");
			break;
		}
		// Write the adjusted packet header
		if(fwrite(rechdr, 1, sizeof(pcaprec_hdr_t), outfile) != sizeof(pcaprec_hdr_t)){
			printf("Error: unable to write pcap record header to output file!\n");				
			return(0);
		}
		// Write the packet data
		if(fwrite(memblock, 1, caplen, outfile) != caplen){
			printf("Error: unable to write frame to output pcap file\n");
			return(0);
		}
		count++;
	}
	if(rechdr != NULL) free(rechdr);

	return(count);
}

int main(int argc, char *argv[]){
// The main function basically just calls other functions to do the work.
	params_t			*parameters = NULL;
	FILE				*infile = NULL,
						*outfile = NULL;
	
	// Parse our command line parameters and verify they are usable. If not, show help.
	parameters = parseParams(argc, argv);
	if(parameters == NULL){
		printf("capshift: a utility to adjust the timestamps of pcap files by a fixed offset.\n");
		printf("Version %s, %s\n\n", SWVERSION, SWRELEASEDATE);
		printf("Usage:\n");
		printf("%s -r inputcapfile -w outputcapfile -o offset \n\n",argv[0]);
		printf("Where inputcapfile is a tcpdump-style .cap file\n");
		printf("outputcapfile is the file where the time-shifted version will be saved\n");
		printf("offset is the number of seconds to shift by (e.g. -1.5, +0.200)\n");
		return(1);
	}
	
	// Attempt to open the input capture file for reading:
	infile = fopen(parameters->infile,"rb");
	if (infile == NULL) {
		printf("\nError!\nUnable to open input capture file!\n");
		return(1);
	}
	// Attempt to open the output capture file for writing:
	outfile = fopen(parameters->outfile, "wb");
	if(outfile == NULL){
		printf("Error - could not open output file!\n");
		return(1);
	}
	
	printf("\n%d frames processed.\n", parse_pcap(infile, outfile, parameters->sign, parameters->secs, parameters->usecs));

	fclose(infile);
	fclose(outfile);
	
	return(0);
}


