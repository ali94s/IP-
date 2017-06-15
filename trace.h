
#pragma once 
#include<stdio.h>

#define __DEBUG
#ifdef __DEBUG

#define fout stdout
#define Trace(...) fprintf(fout,"file[%s]func[%s]line[%d]#",__FILE__,__func__,__LINE__);\
	fprintf(stdout,__VA_ARGS__);\
	fprintf(fout,"\n");
#else
#define Trace(...)
#endif
