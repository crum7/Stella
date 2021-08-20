#include <stdio.h>
#include <string.h>
#include <err.h>
#include <stdlib.h>
#define BUFFER_SIZE 256
#define RESET   "\033[0m"        /*RESET*/
#define RED     "\033[31m"      /* Red */
#define UNDER "\x1b[4m"  /*Underline*/

int main(int argc,char *argv[]);
void online(char *argv[]);
void hashes(char *argv[]);
void gets(char *argv[],int *blacklist);
void downloads(char *argv[],int *blacklist);
void sets(char *argv[],int *blacklist);
void regs(char *argv[],int *blacklist);
void starts(char *argv[],int *blacklist);
void files(char *argv[],int *blacklist);
void resources(char *argv[],int *blacklist);
void computers(char *argv[],int *blacklist);
void locals(char *argv[],int *blacklist);
void devices(char *argv[],int *blacklist);
void exes(char *argv[],int *blacklist);
void sleeps(char *argv[],int *blacklist);
void internets(char *argv[],int *blacklist);
void dlls(char *argv[],int *blacklist);
void others(char *argv[],int *blacklist);
void blacklists(int *blacklist);










int main(int argc, char *argv[])
{
    printf("%sの静的解析結果\n\n",argv[1]);
    int blacklist[BUFFER_SIZE]={};
    blacklist[0]=1;

    online(argv);
    hashes(argv);
    gets(argv,blacklist);
    downloads(argv,blacklist);
    sets(argv,blacklist);
    regs(argv,blacklist);
    starts(argv,blacklist);
    files(argv,blacklist);
    resources(argv,blacklist);
    computers(argv,blacklist);
    locals(argv,blacklist);
    devices(argv,blacklist);
    exes(argv,blacklist);
    sleeps(argv,blacklist);
    internets(argv,blacklist);
    dlls(argv,blacklist);
    others(argv,blacklist);
    blacklists(blacklist);


    exit (EXIT_SUCCESS);
}





void online(char *argv[])
{
//HybridAnlysis/VirusTotal
    FILE *fp=NULL;
    char buf[BUFFER_SIZE];
    char command0[BUFFER_SIZE];
    char *search="md5sum";
    char command1[BUFFER_SIZE];
    char *sha256="sha256sum";

    sprintf(command0,"%s %s | cut -d ' ' -f 1\n",search, argv[1]);


    if((fp=popen(command0, "r"))==NULL){
        err(EXIT_FAILURE, "%s", search);
    }
    printf("-------------------------------オンラインデータベース\n");
    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        //(void) fputs(buf,stdout);
        printf("HYBIRD  ANALYSES\n");
        printf("https://www.hybrid-analysis.com/search?query=%s\n",buf);
        printf("VIRUS TOTAL\n");
        printf("https://www.virustotal.com/gui/search/%s\n\n\n",buf);
    }
    (void) pclose(fp);

}






void hashes(char *argv[])
{
    FILE *fp=NULL;
    char buf[BUFFER_SIZE];
    char command[BUFFER_SIZE];
    char *md5="md5sum";
    char command1[BUFFER_SIZE];
    char *sha256="sha256sum";
    char command2[BUFFER_SIZE];
    char *sha1="sha1sum";
    char command3[BUFFER_SIZE];
    char *file="file";

    printf("-------------------------------ハッシュ値\n");

//md5sum
    sprintf(command,"%s %s | cut -d ' ' -f 1\n",md5, argv[1]);

    if((fp=popen(command, "r"))==NULL){
        err(EXIT_FAILURE, "%s", md5);
    }
    printf("md5sum\n");
    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        (void) fputs(buf,stdout);
    }
    (void) pclose(fp);


//sha256sum
    sprintf(command1,"%s %s | cut -d ' ' -f 1\n",sha256, argv[1]);

    if((fp=popen(command1, "r"))==NULL){
        err(EXIT_FAILURE, "%s", sha256);
    }
    printf("\n");
    printf("sha256sum\n");
    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        (void) fputs(buf,stdout);
    }
    (void) pclose(fp);


//sha1sum
    sprintf(command2,"%s %s | cut -d ' ' -f 1\n",sha1, argv[1]);

    if((fp=popen(command2, "r"))==NULL){
        err(EXIT_FAILURE, "%s", sha1);
    }
    printf("\n");
    printf("sha1sum\n");
    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        (void) fputs(buf,stdout);
    }
    (void) pclose(fp);

//xxd
    char command01[BUFFER_SIZE];
    char *xxd="xxd";
    char *add="| head -1";

    sprintf(command01,"%s %s %s\n",xxd, argv[1],add);


    if((fp=popen(command01, "r"))==NULL){
        err(EXIT_FAILURE, "%s", xxd);
    }
    printf("\n");
    printf("xxd\n");
    char *jud="00000000: 4d5a 9000 0300 0000 0400 0000 ffff 0000  MZ..............\n";

    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        char *qw=buf;
        printf("%s",buf);

        if (strcmp(jud,qw)==0){
            printf("%sは、実行ファイルです。\n",argv[1]);
        }
    }
    (void) pclose(fp);
















//file


    char windo[BUFFER_SIZE];
    char windows[BUFFER_SIZE];


    sprintf(command3,"%s %s\n",file, argv[1]);


    if((fp=popen(command3, "r"))==NULL){
        err(EXIT_FAILURE, "%s", file);
    }
    printf("\n");
    printf("file\n");
    //char *win="PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows";
    
    //sprintf(windo,"%s: %s\n",argv[1],win);

    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        char *wind=buf;
        printf("%s",buf);
        
        char *win="PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows";
        sprintf(windo,"%s: %s\n",argv[1],win);
        if (strcmp(windo,wind)==0){
            printf("Windows7で動く32ビットの実行ファイルです。\n");
            break;
        }
        char *window="PE32+ executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows";
        sprintf(windows,"%s: %s\n",argv[1],window);
        if (strcmp(windows,wind)==0){
            printf("Windowsで動く64ビットの実行ファイルです。\n");
            break;
        }

    }
    (void) pclose(fp);
}







//blacklistのstrings
/*



1 GetForeGroundWindow
2 GetVolumeInformation
3 GetVolumeInformationw
4 GetWindowThreadProcessId
5 GetLastInputInfo
6 GetAsyncKeyState
7 GetProcessesByName
8 GetKeyboardState
9 GetKeyboardType
10 GetCurrentProcessId
11 GetExitCodeProcess
12 GetCommandLine
13 GetCommandLineA
14 GetCommandLineW
15 GetLocaleInfo
16 GetLocaleInfoA
17 GetLocaleInfoW
18 GetStartupInfoA
19 SHGetSpecialFolderLocation

2,3,Volume
1,2 GUI



20 set_UseShellExecute
21 SetEnvironmentVariable
22 SetWindowsHookEx
23 EmptyWorkingSet
24 InternetSetOptionW
25 RegSetValue
26 NtSetInformationProcess
27 InternetSetOption


30 DownloadData
31 DownloadFile




40 RegDeleteValue
41 RegDeleteKey
42 RegCreateKey
43 RegCreateKeyExW
44 RegCreateKeyA
45 RegCreateKeyW
46 RegCreateKeyEx
47 RegEnumKey


60 RestartToolStripMenuItem
61 ProcessStartInfo
62 get_StartupPath
63 get_StartInfo


70 MoveFileEx
71 MoveFileW
72 MoveFileExW
73 WriteFile
74 UnmapViewOfFile
75 MapViewOfFile
76 DeleteFileW
77 DeleteFile
78 DeleteFileA
79 InternetReadFile

80 BeginUpdateResource
81 UpdateResource
82 EndUpdateResource
83 FindResourceW
84 FindResourceA
85 FindResourceExA
86 FindResourceExW
87 LoadResource
88 Lockresource
89 SizeOfResource



90 ComputerInfo
91 get_Computer

100 get_LocalTime

109 cmd.exe
110 Sleep
111 InternetOpen
112 InternetOpenUrl

120 SHELL32.dll

121 Extract
122 mouse_event
123 BlockInput
124 OpenThread
125 SuspendThread
126 BeginInvoke
127 MapVirtualKey
128 AsyncCallback
129 Send
130 VirtualProtect
131 SHChangeNotify
132 AdjustTokenPrivileges
133 OpenProcessToken
134 get_exploitable_systems
135 get_domaincontroller
136 GET_USER
137 FindResouce
138 ShellExecuteExW





*/


























//strings_get
void gets(char *argv[],int *blacklist)
{
/*
1 GetForeGroundWindow
2 GetVolumeInformation
3 GetVolumeInformationw
4 GetWindowThreadProcessId
5 GetLastInputInfo
6 GetAsyncKeyState
7 GetProcessesByName
8 GetKeyboardState
9 GetKeyboardType
10 GetCurrentProcessId
11 GetExitCodeProcess
12 GetCommandLine
13 GetCommandLineA
14 GetCommandLineW
15 GetLocaleInfo
16 GetLocaleInfoA
17 GetLocaleInfoW
18 GetStartupInfoA
19 SHGetSpecialFolderLocation
*/

    FILE *fp=NULL;
    char buf[BUFFER_SIZE];
    char command4[BUFFER_SIZE];
    char *strings="./floss";
    char *get=" | grep Get";

    sprintf(command4,"%s %s %s\n",strings, argv[1], get);


    if((fp=popen(command4, "r"))==NULL){
        err(EXIT_FAILURE, "%s", strings);
    }
    printf("\n");
    printf("-------------------------------GET関連\n");

    char *get1="GetForegroundWindow\n";
    char *get2="GetVolumeInformation\n";
    char *get3="GetVolumeInformationW\n";
    char *get4="GetWindowThreadProcessId\n";
    char *get5="GetLastInputInfo\n";
    char *get6="GetAsyncKeyState\n";
    char *get7="GetProcessesByName\n";
    char *get8="GetKeyboardState\n";
    char *get9="GetKeyboardType\n";
    char *get10="GetCurrentProcessId\n";
    char *get11="GetExitCodeProcess\n";
    char *get12="GetCommandLine\n";
    char *get13="GetCommandLineA\n";
    char *get14="GetCommandLineW\n";
    char *get15="GetLocaleInfo\n";
    char *get16="GetLocaleInfoA\n";
    char *get17="GetLocaleInfoW\n";
    char *get18="GetStartupInfoA\n";
    char *get19="SHGetSpecialFolderLocation\n";



    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        char *get_conf=buf;
        //printf("%s",buf);        

        if(strcmp(get1,get_conf)==0){
            blacklist[1]=1;
            printf(RED "%s",get1);
            printf(RESET);
            
        }
        else if(strcmp(get2,get_conf)==0){
            blacklist[2]=1;
            printf(RED "%s",get2);
            printf(RESET);
        }
        else if(strcmp(get3,get_conf)==0){
            blacklist[3]=1;
            printf(RED "%s",get3);
            printf(RESET);
        }
        else if(strcmp(get4,get_conf)==0){
            blacklist[4]=1;
            printf(RED "%s",get4);
            printf(RESET);
        }
        else if(strcmp(get5,get_conf)==0){
            blacklist[5]=1;
            printf(RED "%s",get5);
            printf(RESET);
        }
        else if(strcmp(get6,get_conf)==0){
            blacklist[6]=1;
            printf(RED "%s",get6);
            printf(RESET);
        }
        else if(strcmp(get7,get_conf)==0){
            blacklist[7]=1;
            printf(RED "%s",get7);
            printf(RESET);
        }
        else if(strcmp(get8,get_conf)==0){
            blacklist[8]=1;
            printf(RED "%s",get8);
            printf(RESET);
        }
        else if(strcmp(get9,get_conf)==0){
            blacklist[9]=1;
            printf(RED "%s",get9);
            printf(RESET);
        }
        else if(strcmp(get10,get_conf)==0){
            blacklist[10]=1;
            printf(RED "%s",get10);
            printf(RESET);
        }
        else if(strcmp(get11,get_conf)==0){
            blacklist[11]=1;
            printf(RED "%s",get11);
            printf(RESET);
        }
        else if(strcmp(get12,get_conf)==0){
            blacklist[12]=1;
            printf(RED "%s",get12);
            printf(RESET);
        }
        else if(strcmp(get13,get_conf)==0){
            blacklist[13]=1;
            printf(RED "%s",get13);
            printf(RESET);
        }
        else if(strcmp(get14,get_conf)==0){
            blacklist[14]=1;
            printf(RED "%s",get14);
            printf(RESET);
        }
        else if(strcmp(get15,get_conf)==0){
            blacklist[15]=1;
            printf(RED "%s",get15);
            printf(RESET);
        }
        else if(strcmp(get16,get_conf)==0){
            blacklist[16]=1;
            printf(RED "%s",get16);
            printf(RESET);
        }
        else if(strcmp(get17,get_conf)==0){
            blacklist[17]=1;
            printf(RED "%s",get17);
            printf(RESET);
        }
        else if(strcmp(get18,get_conf)==0){
            blacklist[18]=1;
            printf(RED "%s",get18);
            printf(RESET);
        }
        else if(strcmp(get19,get_conf)==0){
            blacklist[19]=1;
            printf(RED "%s",get19);
            printf(RESET);
        }else{
            printf("%s",get_conf);
        }
    }
    (void) pclose(fp);
}











//strings_set
void sets(char *argv[],int *blacklist)
{
    FILE *fp=NULL;
    char buf[BUFFER_SIZE];
    char command5[BUFFER_SIZE];
    char *strings="./floss";
    char *set=" | grep -i Set";


    sprintf(command5,"%s %s %s\n",strings, argv[1], set);

    if((fp=popen(command5, "r"))==NULL){
        err(EXIT_FAILURE, "%s", strings);
    }
    printf("\n\n");
    printf("-------------------------------SET関連\n");

/*
20 set_UseShellExecute
21 SetEnvironmentVariable
22 SetWindowsHookEx
23 EmptyWorkingSet
24 InternetSetOptionW
25 RegSetValue
26 NtSetInformationProcess
27 InternetSetOption
*/

    char *set20="set_UseShellExecute\n";
    char *set21="SetEnvironmentVariable\n";
    char *set22="SetWindowsHookEx\n";
    char *set23="EmptyWorkingSet\n";
    char *set24="InternetSetOptionW\n";
    char *set25="RegSetValue\n";
    char *set26="NtSetInformationProcess\n";
    char *set27="InternetSetOption\n";


    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        char *set_conf=buf;
        if(strcmp(set20,set_conf)==0){
            blacklist[20]=1;
            printf(RED "%s",set20);
            printf(RESET);
        }
        else if(strcmp(set21,set_conf)==0){
            blacklist[21]=1;
            printf(RED "%s",set21);
            printf(RESET);
        }
        else if(strcmp(set22,set_conf)==0){
            blacklist[22]=1;
            printf(RED "%s",set22);
            printf(RESET);
        }
        else if(strcmp(set23,set_conf)==0){
            blacklist[23]=1;
            printf(RED "%s",set23);
            printf(RESET);
        }
        else if(strcmp(set24,set_conf)==0){
            blacklist[24]=1;
            printf(RED "%s",set24);
            printf(RESET);
        }
        else if(strcmp(set25,set_conf)==0){
            blacklist[25]=1;
            printf(RED "%s",set25);
            printf(RESET);
        }
        else if(strcmp(set26,set_conf)==0){
            blacklist[26]=1;
            printf(RED "%s",set26);
            printf(RESET);
        }
        else if(strcmp(set27,set_conf)==0){
            blacklist[27]=1;
            printf(RED "%s",set27);
            printf(RESET);
        }else{
            printf("%s",set_conf);
        }
        
    }
    (void) pclose(fp);

}






//strings_Download
void downloads(char *argv[],int *blacklist)
{
    FILE *fp=NULL;
    char buf[BUFFER_SIZE];
    char command06[BUFFER_SIZE];
    char *strings="./floss";
    char *down=" | grep -i down";


    sprintf(command06,"%s %s %s\n",strings, argv[1], down);


    if((fp=popen(command06, "r"))==NULL){
        err(EXIT_FAILURE, "%s", strings);
    }
    printf("\n\n");
    printf("-------------------------------DOWNLOAD関連\n");
/*
30 DownloadData
31 DownloadFile
*/

    char *download30="DownloadData\n";
    char *download31="DownloadFile\n";

    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        char *download_conf=buf;

        if(strcmp(download_conf,download30)==0){
            blacklist[30]=1;
            printf(RED "%s",download30);
            printf(RESET);
        }
        else if(strcmp(download_conf,download31)==0){
            blacklist[31]=1;
            printf(RED "%s",download31);
            printf(RESET);
        }

    }
    (void) pclose(fp);
    
}







//strings_regs
void regs(char *argv[],int *blacklist)
{
    FILE *fp=NULL;
    char buf[BUFFER_SIZE];
    char command07[BUFFER_SIZE];
    char *strings="./floss";
    char *reg=" | grep Reg";


    sprintf(command07,"%s %s %s\n",strings, argv[1], reg);


    if((fp=popen(command07, "r"))==NULL){
        err(EXIT_FAILURE, "%s", strings);
    }
    printf("\n\n");
    printf("-------------------------------Reg関連\n");
/*
40 RegDeleteValue
41 RegDeleteKey
42 RegCreateKey
43 RegCreateKeyExW
44 RegCreateKeyA
45 RegCreateKeyW
46 RegCreateKeyEx
47 RegEnumKey
*/
    char *regs40="RegDeleteValue\n";
    char *regs41="RegDeleteKey\n";
    char *regs42="RegCreateKey\n";
    char *regs43="RegCreateKeyExW\n";
    char *regs44="RegCreateKeyA\n";
    char *regs45="RegCreateKeyW\n";
    char *regs46="RegCreateKeyEx\n";
    char *regs47="RegEnumKey\n";

    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        char *regs_conf=buf;
        if(strcmp(regs40,regs_conf)==0){
            blacklist[40]=1;
            printf(RED "%s",regs40);
            printf(RESET);
        }
        else if(strcmp(regs41,regs_conf)==0){
            blacklist[41]=1;
            printf(RED "%s",regs41);
            printf(RESET);
        }
        else if(strcmp(regs42,regs_conf)==0){
            blacklist[42]=1;
            printf(RED "%s",regs42);
            printf(RESET);
        }
        else if(strcmp(regs43,regs_conf)==0){
            blacklist[43]=1;
            printf(RED "%s",regs43);
            printf(RESET);
        }
        else if(strcmp(regs44,regs_conf)==0){
            blacklist[44]=1;
            printf(RED "%s",regs44);
            printf(RESET);
        }
        else if(strcmp(regs45,regs_conf)==0){
            blacklist[45]=1;
            printf(RED "%s",regs45);
            printf(RESET);
        }
        else if(strcmp(regs46,regs_conf)==0){
            blacklist[46]=1;
            printf(RED "%s",regs46);
            printf(RESET);
        }
        else if(strcmp(regs47,regs_conf)==0){
            blacklist[47]=1;
            printf(RED "%s",regs47);
            printf(RESET);
        }
        else{
            printf("%s",regs_conf);
        }

    }
    (void) pclose(fp);
}



//strings_start
void starts(char *argv[],int *blacklist)
{

    FILE *fp=NULL;
    char buf[BUFFER_SIZE];
    char command6[BUFFER_SIZE];
    char *strings="./floss";
    char *start=" | grep -i start";


    sprintf(command6,"%s %s %s\n",strings, argv[1], start);


    if((fp=popen(command6, "r"))==NULL){
        err(EXIT_FAILURE, "%s", strings);
    }
    printf("\n\n");
    printf("-------------------------------START関連\n");
/*
60 RestartToolStripMenuItem
61 ProcessStartInfo
62 get_StartupPath
63 get_StartInfo
*/
    char *start60="RestartToolStripMenuItem\n";
    char *start61="ProcessStartInfo\n";
    char *start62="get_StartupPath\n";
    char *start63="get_StartInfo\n";

    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        char *start_conf=buf;
        if(strcmp(start60,start_conf)==0){
            blacklist[60]=1;
            printf(RED "%s",start60);
            printf(RESET);
        }
        else if(strcmp(start61,start_conf)==0){
            blacklist[61]=1;
            printf(RED "%s",start61);
            printf(RESET);
        }
        else if(strcmp(start62,start_conf)==0){
            blacklist[62]=1;
            printf(RED "%s",start62);
            printf(RESET);
        }
        else if(strcmp(start63,start_conf)==0){
            blacklist[63]=1;
            printf(RED "%s",start63);
            printf(RESET);
        }
        else{
            printf("%s",start_conf);
        }

    }
    (void) pclose(fp);

}







//strings_File
void files(char *argv[],int *blacklist)
{

    FILE *fp=NULL;
    char buf[BUFFER_SIZE];
    char command7[BUFFER_SIZE];
    char *strings="./floss";
    char *stringsfile=" | grep -i file";


    sprintf(command7,"%s %s %s\n",strings, argv[1], stringsfile);


    if((fp=popen(command7, "r"))==NULL){
        err(EXIT_FAILURE, "%s", strings);
    }
    printf("\n\n");
    printf("-------------------------------File関連\n");
/*
70 MoveFileEx
71 MoveFileW
72 MoveFileExW
73 WriteFile
74 UnmapViewOfFile
75 MapViewOfFile
76 DeleteFileW
77 DeleteFile
78 DeleteFileA
79 InternetReadFile
*/
    char *file70="MoveFileEx\n";
    char *file71="MoveFileW\n";
    char *file72="MoveFileExW\n";
    char *file73="WriteFile\n";
    char *file74="UnmapViewOfFile\n";
    char *file75="MapViewOfFile\n";
    char *file76="DeleteFileW\n";
    char *file77="DeleteFile\n";
    char *file78="DeleteFileA\n";
    char *file79="InternetReadFile\n";

    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        char *file_conf=buf;
        if(strcmp(file70,file_conf)==0){
            blacklist[70]=1;
            printf(RED "%s",file70);
            printf(RESET);
        }
        else if(strcmp(file71,file_conf)==0){
            blacklist[71]=1;
            printf(RED "%s",file71);
            printf(RESET);
        }
        else if(strcmp(file72,file_conf)==0){
            blacklist[72]=1;
            printf(RED "%s",file72);
            printf(RESET);
        }
        else if(strcmp(file73,file_conf)==0){
            blacklist[73]=1;
            printf(RED "%s",file73);
            printf(RESET);
        }
        else if(strcmp(file74,file_conf)==0){
            blacklist[74]=1;
            printf(RED "%s",file74);
            printf(RESET);
        }
        else if(strcmp(file75,file_conf)==0){
            blacklist[75]=1;
            printf(RED "%s",file75);
            printf(RESET);
        }
        else if(strcmp(file76,file_conf)==0){
            blacklist[76]=1;
            printf(RED "%s",file76);
            printf(RESET);
        }
        else if(strcmp(file77,file_conf)==0){
            blacklist[77]=1;
            printf(RED "%s",file77);
            printf(RESET);
        }
        else if(strcmp(file78,file_conf)==0){
            blacklist[78]=1;
            printf(RED "%s",file78);
            printf(RESET);
        }
        else if(strcmp(file79,file_conf)==0){
            blacklist[79]=1;
            printf(RED "%s",file79);
            printf(RESET);
        }
        else{
            printf("%s",file_conf);
        }
    }
    (void) pclose(fp);
}








//strings resource
void resources(char *argv[],int *blacklist)
{
    FILE *fp=NULL;
    char buf[BUFFER_SIZE];
    char command08[BUFFER_SIZE];
    char *strings="./floss";
    char *resource=" | grep -i resource";


    sprintf(command08,"%s %s %s\n",strings, argv[1], resource);


    if((fp=popen(command08, "r"))==NULL){
        err(EXIT_FAILURE, "%s", strings);
    }
    printf("\n\n");
    printf("-------------------------------RESOURCE関連\n");
/*
80 BeginUpdateResource
81 UpdateResource
82 EndUpdateResource
83 FindResourceW
84 FindResourceA
85 FindResourceExA
86 FindResourceExW
87 LoadResource
88 Lockresource
89 SizeOfResource
*/
    char *resource80="BeginUpdateResource\n";
    char *resource81="UpdateResource\n";
    char *resource82="EndUpdateResource\n";
    char *resource83="FindResourceW\n";
    char *resource84="FindResourceA\n";
    char *resource85="FindResourceExA\n";
    char *resource86="FindResourceExW\n";
    char *resource87="LoadResource\n";
    char *resource88="LockResource\n";
    char *resource89="SizeOfResource\n";

    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        char *resourse_conf=buf;
        if(strcmp(resource80,resourse_conf)==0){
            blacklist[80]=1;
            printf(RED "%s",resource80);
            printf(RESET);
        }
        else if(strcmp(resource81,resourse_conf)==0){
            blacklist[81]=1;
            printf(RED "%s",resource81);
            printf(RESET);
        }
        else if(strcmp(resource82,resourse_conf)==0){
            blacklist[82]=1;
            printf(RED "%s",resource82);
            printf(RESET);
        }
        else if(strcmp(resource83,resourse_conf)==0){
            blacklist[83]=1;
            printf(RED "%s",resource83);
            printf(RESET);
        }
        else if(strcmp(resource84,resourse_conf)==0){
            blacklist[84]=1;
            printf(RED "%s",resource84);
            printf(RESET);
        }
        else if(strcmp(resource85,resourse_conf)==0){
            blacklist[85]=1;
            printf(RED "%s",resource85);
            printf(RESET);
        }
        else if(strcmp(resource86,resourse_conf)==0){
            blacklist[86]=1;
            printf(RED "%s",resource86);
            printf(RESET);
        }
        else if(strcmp(resource87,resourse_conf)==0){
            blacklist[87]=1;
            printf(RED "%s",resource87);
            printf(RESET);
        }
        else if(strcmp(resource88,resourse_conf)==0){
            blacklist[88]=1;
            printf(RED "%s",resource88);
            printf(RESET);
        }
        else if(strcmp(resource89,resourse_conf)==0){
            blacklist[89]=1;
            printf(RED "%s",resource89);
            printf(RESET);
        }else{
            printf("%s",resourse_conf);
        }
    }
    (void) pclose(fp);
}



//computer
void computers(char *argv[],int *blacklist)
{
    FILE *fp=NULL;
    char buf[BUFFER_SIZE];
    char command8[BUFFER_SIZE];
    char *strings="./floss";
    char *computer=" | grep -i computer";


    sprintf(command8,"%s %s %s\n",strings, argv[1], computer);


    if((fp=popen(command8, "r"))==NULL){
        err(EXIT_FAILURE, "%s", strings);
    }
    printf("\n\n");
    printf("-------------------------------computer関連\n");
/*
90 ComputerInfo
91 get_Computer
*/
    char *computer90="ComputerInfo\n";
    char *computer91="get_Computer\n";

    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        char *computer_conf=buf;
        if(strcmp(computer90,computer_conf)==0){
            blacklist[90]=1;
            printf(RED "%s",computer90);
            printf(RESET);
        }
        else if(strcmp(computer91,computer_conf)==0){
            blacklist[91]=1;
            printf(RED "%s",computer91);
            printf(RESET);
        }
        else{
            printf("%s",computer_conf);
        }
    }
    (void) pclose(fp);

}



//local
void locals(char *argv[],int *blacklist)
{

    FILE *fp=NULL;
    char buf[BUFFER_SIZE];
    char command9[BUFFER_SIZE];
    char *strings="./floss";
    char *local=" | grep -i local";


    sprintf(command9,"%s %s %s\n",strings, argv[1], local);


    if((fp=popen(command9, "r"))==NULL){
        err(EXIT_FAILURE, "%s", strings);
    }
    printf("\n\n");
    printf("-------------------------------local関連\n");
/*
15 GetLocaleInfo
16 GetLocaleInfoA
17 GetLocaleInfoW
100 get_LocalTime
*/  
    char *local100="get_LocalTime\n";
    char *get15="GetLocaleInfoW\n";
    char *get16="GetLocaleInfoA\n";
    char *get17="GetLocaleInfoW\n";
    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        char *local_conf=buf;
        if(strcmp(local100,local_conf)==0){
            blacklist[100]=1;
            printf(RED "%s",local100);
            printf(RESET);
        }else if(strcmp(get15,local_conf)==0){
            printf(RED "%s",get15);
            printf(RESET);
        
        }else if(strcmp(get16,local_conf)==0){
            printf(RED "%s",get16);
            printf(RESET);
        
        }else if(strcmp(get17,local_conf)==0){
            printf(RED "%s",get17);
            printf(RESET);
        }else{
            printf("%s",local_conf);
        }


    }
    (void) pclose(fp);
}




//device
void devices(char *argv[],int *blacklist)
{
    FILE *fp=NULL;
    char buf[BUFFER_SIZE];
    char command10[BUFFER_SIZE];
    char *strings="./floss";
    char *device=" | grep -i device";


    sprintf(command10,"%s %s %s\n",strings, argv[1], device);


    if((fp=popen(command10, "r"))==NULL){
        err(EXIT_FAILURE, "%s", device);
    }
    printf("\n\n");
    printf("-------------------------------device関連\n");
    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        (void) fputs(buf,stdout);
    }
    (void) pclose(fp);
}




//exe
void exes(char *argv[],int *blacklist)
{
    FILE *fp=NULL;
    char buf[BUFFER_SIZE];
    char command11[BUFFER_SIZE];
    char *strings="./floss";
    char *exe=" | grep -i exe";


    sprintf(command11,"%s %s %s\n",strings, argv[1], exe);


    if((fp=popen(command11, "r"))==NULL){
        err(EXIT_FAILURE, "%s", exe);
    }
    printf("\n\n");
    printf("-------------------------------exe関連\n");
/*
109 cmd.exe
*/
    char *exe109="cmd.exe\n";
    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        char *exe_conf=buf;
        if(strcmp(exe109,exe_conf)==0){
            blacklist[109]=1;
            printf(RED "%s",exe109);
            printf(RESET);
        }else{
            printf("%s",buf);
        }
    }
    (void) pclose(fp);

}



//sleep
void sleeps(char *argv[],int *blacklist)
{

    FILE *fp=NULL;
    char buf[BUFFER_SIZE];
    char command12[BUFFER_SIZE];
    char *strings="./floss";
    char *sleep=" | grep -i sleep";


    sprintf(command12,"%s %s %s\n",strings, argv[1], sleep);


    if((fp=popen(command12, "r"))==NULL){
        err(EXIT_FAILURE, "%s", sleep);
    }
    printf("\n\n");
    printf("-------------------------------sleep関連\n");
/*
110 Sleep
*/
    char *exe109="cmd.exe\n";
    char *sleep110="Sleep\n";
    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        char *sleep_conf=buf;
        if(strcmp(sleep110,sleep_conf)==0){
            blacklist[110]=1;
            printf(RED "%s",sleep110);
            printf(RESET);
        }else{
            printf("%s",buf);
        }
    }
    (void) pclose(fp);

}





//internet
void internets(char *argv[],int *blacklist)
{
    FILE *fp=NULL;
    char buf[BUFFER_SIZE];
    char command010[BUFFER_SIZE];
    char *strings="./floss";
    char *internet=" | grep -i internet";


    sprintf(command010,"%s %s %s\n",strings, argv[1], internet);


    if((fp=popen(command010, "r"))==NULL){
        err(EXIT_FAILURE, "%s", strings);
    }
    printf("\n\n");
    printf("-------------------------------INTERNET関連\n");
/*
24 InternetSetOptionW
27 InternetSetOption
79 InternetReadFile
111 InternetOpen
112 InternetOpenUrl

*/

    char *internet111="InternetOpen\n";
    char *internet112="InternetOpenUrl\n";
    char *internet24="InternetSetOptionW\n";
    char *internet27="InternetSetOption\n";
    char *internet79="InternetReadFile\n";

    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        char *internet_conf=buf;
        if(strcmp(internet111,internet_conf)==0){
            blacklist[111]=1;
            printf(RED "%s",internet111);
            printf(RESET);
        }
        else if(strcmp(internet112,internet_conf)==0){
            blacklist[112]=1;
            printf(RED "%s",internet112);
            printf(RESET);
        }
        else if(strcmp(internet24,internet_conf)==0){

            printf(RED "%s"RESET,internet24);
        }
        else if(strcmp(internet27,internet_conf)==0){

            printf(RED "%s",internet27);
            printf(RESET);
        }
        else if(strcmp(internet79,internet_conf)==0){

            printf(RED "%s",internet79);
            printf(RESET);
        }else{
            printf("%s",buf);
        }
    
}
(void) pclose(fp);
}







void dlls(char *argv[],int *blacklist)
{
//dll
    FILE *fp=NULL;
    char buf[BUFFER_SIZE];
    char command13[BUFFER_SIZE];
    char *strings="./floss";
    char *dll=" | grep -i dll";


    sprintf(command13,"%s %s %s\n",strings, argv[1], dll);


    if((fp=popen(command13, "r"))==NULL){
        err(EXIT_FAILURE, "%s", dll);
    }
    printf("\n\n");
    printf("-------------------------------dll関連\n");
/*
120 SHELL32.dll
*/
    char *dll120="SHELL32.dll\n";

    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        char *dll_conf=buf;
        if(strcmp(dll120,dll_conf)==0){
            blacklist[120]=1;
            printf(RED "%s",dll120);
            printf(RESET);
        }else{
            printf("%s",buf);
        }
    }
    (void) pclose(fp);
}



//others
void others(char *argv[],int *blacklist)
{
    FILE *fp=NULL;
    char buf[BUFFER_SIZE];
    char *strings="./floss";
    char command10101[BUFFER_SIZE];
    sprintf(command10101,"%s %s\n",strings,argv[1]);

    if((fp=popen(command10101, "r"))==NULL){
        err(EXIT_FAILURE, "%s", strings);
    }
    printf("\n\n");
    printf("-------------------------------その他\n");

/*
121 Extract
122 mouse_event
123 BlockInput
124 OpenThread
125 SuspendThread
126 BeginInvoke
127 MapVirtualKey
128 AsyncCallback
129 Send
130 VirtualProtect
131 SHChangeNotify
132 AdjustTokenPrivileges
133 OpenProcessToken
134 get_exploitable_systems
135 get_domaincontroller
136 GET_USER
137 FindResouce
138 ShellExecuteExW
*/

    char *others121="Extract\n";
    char *others122="mouse_event\n";
    char *others123="BlockInput\n";
    char *others124="OpenThread\n";
    char *others125="SuspendThread\n";
    char *others126="BeginInvoke\n";
    char *others127="MapVirtualKey\n";
    char *others128="AsyncCallback\n";
    char *others129="Send\n";
    char *others130="VirtualProtect\n";
    char *others131="SHChangeNotify\n";
    char *others132="AdjustTokenPrivileges\n";
    char *others133="OpenProcessToken\n";
    char *others134="get_exploitable_systems\n";
    char *others135="get_domaincontroller\n";
    char *others136="GET_USER\n";
    char *others137="FindResouce\n";
    char *others138="ShellExecuteExW\n";




    while(fgets(buf,BUFFER_SIZE,fp)!=NULL){
        char *others_conf=buf;
        if(strcmp(others121,others_conf)==0){
            blacklist[121]=1;
            printf(RED "%s",others121);
            printf(RESET);
        }
        if(strcmp(others122,others_conf)==0){
            blacklist[122]=1;
            printf(RED "%s",others122);
            printf(RESET);
        }
        if(strcmp(others123,others_conf)==0){
            blacklist[123]=1;
            printf(RED "%s",others123);
            printf(RESET);
        }
        if(strcmp(others124,others_conf)==0){
            blacklist[124]=1;
            printf(RED "%s",others124);
            printf(RESET);
        }
        if(strcmp(others125,others_conf)==0){
            blacklist[125]=1;
            printf(RED "%s",others125);
            printf(RESET);
        }
        if(strcmp(others126,others_conf)==0){
            blacklist[126]=1;
            printf(RED "%s",others126);
            printf(RESET);
        }
        if(strcmp(others127,others_conf)==0){
            blacklist[127]=1;
            printf(RED "%s",others127);
            printf(RESET);
        }
        if(strcmp(others128,others_conf)==0){
            blacklist[128]=1;
            printf(RED "%s",others128);
            printf(RESET);
        }
        if(strcmp(others129,others_conf)==0){
            blacklist[129]=1;
            printf(RED "%s",others129);
            printf(RESET);
        }
        if(strcmp(others130,others_conf)==0){
            blacklist[130]=1;
            printf(RED "%s",others130);
            printf(RESET);
        }
        if(strcmp(others131,others_conf)==0){
            blacklist[131]=1;
            printf(RED "%s",others131);
            printf(RESET);
        }
        if(strcmp(others132,others_conf)==0){
            blacklist[132]=1;
            printf(RED "%s",others132);
            printf(RESET);
        }
        if(strcmp(others133,others_conf)==0){
            blacklist[133]=1;
            printf(RED "%s",others133);
            printf(RESET);
        }
        if(strcmp(others134,others_conf)==0){
            blacklist[134]=1;
            printf(RED "%s",others134);
            printf(RESET);
        }
        if(strcmp(others135,others_conf)==0){
            blacklist[135]=1;
            printf(RED "%s",others135);
            printf(RESET);
        }
        if(strcmp(others136,others_conf)==0){
            blacklist[136]=1;
            printf(RED "%s",others136);
            printf(RESET);
        }
        if(strcmp(others137,others_conf)==0){
            blacklist[137]=1;
            printf(RED "%s",others137);
            printf(RESET);
        }
        if(strcmp(others138,others_conf)==0){
            blacklist[138]=1;
            printf(RED "%s",others138);
            printf(RESET);
        }
        
    }
    (void) pclose(fp);
}





void blacklists(int *blacklist)
{
    int num=0;
    int  sum=0;
    float ans;
    char *get1="GetForegroundWindow\n";
    char *get2="GetVolumeInformation\n";
    char *get3="GetVolumeInformationW\n";
    char *get4="GetWindowThreadProcessId\n";
    char *get5="GetLastInputInfo\n";
    char *get6="GetAsyncKeyState\n";
    char *get7="GetProcessesByName\n";
    char *get8="GetKeyboardState\n";
    char *get9="GetKeyboardType\n";
    char *get10="GetCurrentProcessId\n";
    char *get11="GetExitCodeProcess\n";
    char *get12="GetCommandLine\n";
    char *get13="GetCommandLineA\n";
    char *get14="GetCommandLineW\n";
    char *get15="GetLocaleInfo\n";
    char *get16="GetLocaleInfoA\n";
    char *get17="GetLocaleInfoW\n";
    char *get18="GetStartupInfoA\n";
    char *get19="SHGetSpecialFolderLocation\n";

    char *set20="set_UseShellExecute\n";
    char *set21="SetEnvironmentVariable\n";
    char *set22="SetWindowsHookEx\n";
    char *set23="EmptyWorkingSet\n";
    char *set24="InternetSetOptionW\n";
    char *set25="RegSetValue\n";
    char *set26="NtSetInformationProcess\n";
    char *set27="InternetSetOption\n";

    char *download30="DownloadData\n";
    char *download31="DownloadFile\n";

    char *regs40="RegDeleteValue\n";
    char *regs41="RegDeleteKey\n";
    char *regs42="RegCreateKey\n";
    char *regs43="RegCreateKeyExW\n";
    char *regs44="RegCreateKeyA\n";
    char *regs45="RegCreateKeyW\n";
    char *regs46="RegCreateKeyEx\n";
    char *regs47="RegEnumKey\n";

    char *start60="RestartToolStripMenuItem\n";
    char *start61="ProcessStartInfo\n";
    char *start62="get_StartupPath\n";
    char *start63="get_StartInfo\n";

    char *file70="MoveFileEx\n";
    char *file71="MoveFileW\n";
    char *file72="MoveFileExW\n";
    char *file73="WriteFile\n";
    char *file74="UnmapViewOfFile\n";
    char *file75="MapViewOfFile\n";
    char *file76="DeleteFileW\n";
    char *file77="DeleteFile\n";
    char *file78="DeleteFileA\n";
    char *file79="InternetReadFile\n";

    char *resource80="BeginUpdateResource\n";
    char *resource81="UpdateResource\n";
    char *resource82="EndUpdateResource\n";
    char *resource83="FindResourceW\n";
    char *resource84="FindResourceA\n";
    char *resource85="FindResourceExA\n";
    char *resource86="FindResourceExW\n";
    char *resource87="LoadResource\n";
    char *resource88="LockResource\n";
    char *resource89="SizeOfResource\n";

    char *computer90="ComputerInfo\n";
    char *computer91="get_Computer\n";
    char *local100="get_LocalTime\n";
    char *exe109="cmd.exe\n";
    char *sleep110="Sleep\n";
    char *internet111="InternetOpen\n";
    char *internet112="InternetOpenUrl\n";
    char *dll120="SHELL32.dll\n";

    char *others121="Extract\n";
    char *others122="mouse_event\n";
    char *others123="BlockInput\n";
    char *others124="OpenThread\n";
    char *others125="SuspendThread\n";
    char *others126="BeginInvoke\n";
    char *others127="MapVirtualKey\n";
    char *others128="AsyncCallback\n";
    char *others129="Send\n";
    char *others130="VirtualProtect\n";
    char *others131="SHChangeNotify\n";
    char *others132="AdjustTokenPrivileges\n";
    char *others133="OpenProcessToken\n";
    char *others134="get_exploitable_systems\n";
    char *others135="get_domaincontroller\n";
    char *others136="GET_USER\n";
    char *others137="FindResouce\n";
    char *others138="ShellExecuteExW\n";
    
    printf("-----------------------------------------------Blacklist検索結果\n");
/*
1 GetForeGroundWindow
4 GetWindowThreadProcessId
GUI
*/

if(blacklist[1]==1 | blacklist[4]==1){
        printf(UNDER"\nGUIを使っている可能性があります。");
        printf(RESET);

        num=0;
        sum=2;
        num=blacklist[0]+blacklist[4];
        printf("%d/%d\n",num,sum);

       if(blacklist[1]==1){
           printf("%s",get1);
       }
        if(blacklist[4]==1){
           printf("%s",get4);
       }
        
}

/*
22 SetWindowsHookEx
5 GetLastInputInfo
6 GetAsyncKeyState
8 GetKeyboardState
9 GetKeyboardType
122 mouse_event
キーロガー

*/

if(blacklist[22]==1 | blacklist[5]==1 | blacklist[6]==1 | blacklist[8]==1 | blacklist[9]==1 | blacklist[122]==1){
        printf(UNDER"\nキーロガーの可能性があります。"RESET);

        num=0;
        sum=6;
        num=blacklist[22]+blacklist[5]+blacklist[6]+blacklist[8]+blacklist[9]+blacklist[122];
        printf("%d/%d\n",num,sum);

       if(blacklist[22]==1){
           printf("%s",set22);
       }
        if(blacklist[5]==1){
           printf("%s",get5);
       }
       if(blacklist[6]==1){
           printf("%s",get6);
       }
        if(blacklist[8]==1){
           printf("%s",get8);
       }
       if(blacklist[9]==1){
           printf("%s",get9);
       }
        if(blacklist[122]==1){
           printf("%s",others122);
       }


        
}

/*
19 SHGetSpecialFolderLocation
21 SetEnvironmentVariable
パス(環境変数)を作成する

*/

if(blacklist[19]==1 | blacklist[21]==1){
        printf(UNDER"\nパス(環境変数)を作成する可能性があります。"RESET);

        num=0;
        sum=2;
        num=blacklist[19]+blacklist[21];
        printf("%d/%d\n",num,sum);

       if(blacklist[19]==1){
           printf("%s",get19);
       }
        if(blacklist[21]==1){
           printf("%s",set21);
       }
        
}

/*
18 GetStartupInfoA
60 RestartToolStripMenuItem
61 ProcessStartInfo
62 get_StartupPath
63 get_StartInfo
パソコンを再起動したときに自動起動する

*/


if(blacklist[18]==1 | blacklist[60]==1|blacklist[61]==1 | blacklist[62]==1|blacklist[63]==1){
        printf(UNDER"\nパソコンを再起動したときに自動起動する可能性があります。"RESET);

        num=0;
        sum=5;
        num=blacklist[18]+blacklist[60]+blacklist[61]+blacklist[62]+blacklist[63];
        printf("%d/%d\n",num,sum);

       if(blacklist[18]==1){
           printf("%s",get18);
       }
        if(blacklist[60]==1){
           printf("%s",start60);
       }
       if(blacklist[61]==1){
           printf("%s",start61);
       }
        if(blacklist[62]==1){
           printf("%s",start62);
       }
       if(blacklist[63]==1){
           printf("%s",start63);
       }
        
        
}

/*
23 EmptyWorkingSet
4 GetWindowThreadProcessId
61 ProcessStartInfo
7 GetProcessesByName
10 GetCurrentProcessId
11 GetExitCodeProcess
26 NtSetInformationProcess
プロセスの作成・削除が行われる

*/


if(blacklist[23]==1 | blacklist[4]==1| blacklist[61]==1 | blacklist[7]==1 | blacklist[10]==1| blacklist[11]==1 | blacklist[26]==1){
        printf(UNDER"\nプロセスの作成・削除が行われる可能性があります。"RESET);

        num=0;
        sum=7;
        num=blacklist[23]+blacklist[4]+blacklist[61]+blacklist[7]+blacklist[10]+blacklist[11]+blacklist[26];
        printf("%d/%d\n",num,sum);

       if(blacklist[23]==1){
           printf("%s",set23);
       }
        if(blacklist[4]==1){
           printf("%s",get4);
       }
       if(blacklist[61]==1){
           printf("%s",start61);
       }
        if(blacklist[7]==1){
           printf("%s",get7);
       }
       if(blacklist[10]==1){
           printf("%s",get10);
       }
        if(blacklist[11]==1){
           printf("%s",get11);
       }
       if(blacklist[26]==1){
           printf("%s",set26);
       }

        
}

/*
70 MoveFileEx
71 MoveFileW
72 MoveFileExW
73 WriteFile
76 DeleteFileW
77 DeleteFile
78 DeleteFileA
ファイルの作成、移動、削除が行われる

*/

if(blacklist[70]==1 | blacklist[71]==1 | blacklist[72]==1 | blacklist[73]==1| blacklist[76]==1 | blacklist[77]==1|blacklist[78]==1){
        printf(UNDER"\nファイルの作成、移動、削除が行われる可能性があります。"RESET);

        num=0;
        sum=7;
        num=blacklist[70]+blacklist[71]+blacklist[72]+blacklist[73]+blacklist[76]+blacklist[77]+blacklist[78];
        printf("%d/%d\n",num,sum);

       if(blacklist[70]==1){
           printf("%s",file70);
       }
        if(blacklist[71]==1){
           printf("%s",file71);
       }
       if(blacklist[72]==1){
           printf("%s",file72);
       }
        if(blacklist[73]==1){
           printf("%s",file73);
       }
       if(blacklist[76]==1){
           printf("%s",file76);
       }
        if(blacklist[77]==1){
           printf("%s",file77);
       }
       if(blacklist[78]==1){
           printf("%s",file78);
       }

        
}

/*
80 BeginUpdateResource
81 UpdateResource
82 EndUpdateResource
30 DownloadData
31 DownloadFile
データをダウンロードし、システムに適用させる

*/


if(blacklist[80]==1 | blacklist[81]==1 | blacklist[82]==1 | blacklist[30]==1 | blacklist[31]==1){
        printf(UNDER"\nデータをダウンロードし、システムに適用させる可能性があります。"RESET);

        num=0;
        sum=5;
        num=blacklist[80]+blacklist[81]+blacklist[82]+blacklist[30]+blacklist[31];
        printf("%d/%d\n",num,sum);

       if(blacklist[80]==1){
           printf("%s",resource80);
       }
        if(blacklist[81]==1){
           printf("%s",resource81);
       }
       if(blacklist[82]==1){
           printf("%s",resource82);
       }
        if(blacklist[30]==1){
           printf("%s",download30);
       }
       if(blacklist[31]==1){
           printf("%s",download31);
       }
        
}

/*
83 FindResourceW
84 FindResourceA
85 FindResourceExA
86 FindResourceExW
87 LoadResource
88 Lockresource
89 SizeOfResource
ドロッパー

*/


if(blacklist[83]==1 | blacklist[84]==1 | blacklist[85]==1 | blacklist[86]==1|blacklist[87]==1 |blacklist[88]==1|blacklist[89]==1){
        printf(UNDER"\nこのマルウェアは、ドロッパーの可能性があります。"RESET);

        num=0;
        sum=7;
        num=blacklist[83]+blacklist[84]+blacklist[85]+blacklist[86]+blacklist[87]+blacklist[88]+blacklist[89];
        printf("%d/%d\n",num,sum);

       if(blacklist[83]==1){
           printf("%s",resource83);
       }
        if(blacklist[84]==1){
           printf("%s",resource84);
       }
       if(blacklist[85]==1){
           printf("%s",resource85);
       }
        if(blacklist[86]==1){
           printf("%s",resource86);
       }
       if(blacklist[87]==1){
           printf("%s",resource87);
       }
        if(blacklist[88]==1){
           printf("%s",resource88);
       }
       if(blacklist[89]==1){
           printf("%s",resource89);
       }
        
}

/*
20 set_UseShellExecute
138 ShellExecuteExW
12 GetCommandLine
13 GetCommandLineA
14 GetCommandLineW
109 cmd.exe
120 SHELL32.dll
shellやコマンドプロンプトが使われる

*/


if(blacklist[20]==1 | blacklist[138]==1 | blacklist[12]==1 | blacklist[13]==1 |blacklist[14]==1 | blacklist[109]==1| blacklist[120]==1){
        printf(UNDER"\nshellやコマンドプロンプトが使われる可能性があります。"RESET);

        num=0;
        sum=7;
        num=blacklist[20]+blacklist[138]+blacklist[12]+blacklist[13]+blacklist[14]+blacklist[109]+blacklist[120];
        printf("%d/%d\n",num,sum);

       if(blacklist[20]==1){
           printf("%s",set20);
       }
        if(blacklist[138]==1){
           printf("%s",others138);
       }
       if(blacklist[12]==1){
           printf("%s",get12);
       }
        if(blacklist[13]==1){
           printf("%s",get13);
       }
       if(blacklist[14]==1){
           printf("%s",get14);
       }
        if(blacklist[109]==1){
           printf("%s",exe109);
       }
       if(blacklist[120]==1){
           printf("%s",dll120);
       }
        
        
}

/*
124 OpenThread
125 SuspendThread
110 Sleep
ユーザーの意図しないスリープをする

*/

if(blacklist[124]==1 | blacklist[125]==1 | blacklist[110]==1){
        printf(UNDER"\nユーザーの意図しないスリープをする可能性があります。"RESET);

        num=0;
        sum=3;
        num=blacklist[124]+blacklist[125]+blacklist[110];
         printf("%d/%d\n",num,sum);

       if(blacklist[124]==1){
           printf("%s",others124);
       }
        if(blacklist[125]==1){
           printf("%s",others125);
       }
        if(blacklist[110]==1){
           printf("%s",sleep110);
       }
        
}

/*
111 InternetOpen
112 InternetOpenUrl
30 DownloadData
31 DownloadFile
129 Send
外部と通信

*/


if(blacklist[111]==1 | blacklist[112]==1 | blacklist[30]==1 | blacklist[31]==1 | blacklist[129]==1){
        printf(UNDER"\n外部と通信する可能性があります。"RESET);

        num=0;
        sum=5;
        num=blacklist[111]+blacklist[112]+blacklist[30]+blacklist[31]+blacklist[129];
        printf("%d/%d\n",num,sum);
       if(blacklist[111]==1){
           printf("%s",internet111);
       }
        if(blacklist[112]==1){
           printf("%s",internet112);
       }
        if(blacklist[30]==1){
           printf("%s",download30);
       }
        if(blacklist[31]==1){
           printf("%s",download31);
       }
        if(blacklist[129]==1){
           printf("%s",others129);
       }
        
}

/*
79 InternetReadFile
27 InternetSetOption
24 InternetSetOptionW
111 InternetOpen
112 InternetOpenUrl
C2通信が行われる

*/

if(blacklist[79]==1 | blacklist[27]==1 | blacklist[24]==1 | blacklist[111]==1 | blacklist[112]==1){
        printf(UNDER"\nC2通信が行われる可能性があります。"RESET);

        num=0;
        sum=5;
        num=blacklist[79]+blacklist[27]+blacklist[24]+blacklist[111]+blacklist[112];
        printf("%d/%d\n",num,sum);

       if(blacklist[79]==1){
           printf("%s",file79);
       }
        if(blacklist[27]==1){
           printf("%s",set27);
       }
        if(blacklist[24]==1){
           printf("%s",set24);
       }
        if(blacklist[111]==1){
           printf("%s",internet111);
       }
        if(blacklist[112]==1){
           printf("%s",internet112);
       }
        
}

/*
121 Extract
123 BlockInput
126 BeginInvoke
127 MapVirtualKey
128 AsyncCallback
74 UnmapViewOfFile
75 MapViewOfFile
131 SHChangeNotify
132 AdjustTokenPrivileges
133 OpenProcessToken
137 FindResouce
ファイルに何らかの影響を及ぼす可能性があります。
*/
if(blacklist[121]==1 | blacklist[123]==1| blacklist[126]==1 | blacklist[127]==1 | blacklist[128]==1 | blacklist[74]==1 | blacklist[75]==1 | blacklist[131]==1 | blacklist[132]==1 | blacklist[133]==1 | blacklist[137]==1){
        printf(UNDER"\nファイルに何らかの影響を及ぼす可能性があります。"RESET);

        num=0;
        sum=11;
        num=blacklist[121]+blacklist[123]+blacklist[126]+blacklist[127]+blacklist[128]+blacklist[74]+blacklist[75]+blacklist[131]+blacklist[132]+blacklist[133]+blacklist[137];
        printf("%d/%d\n",num,sum);

       if(blacklist[74]==1){
           printf("%s",file74);
       }
        if(blacklist[75]==1){
           printf("%s",file75);
       }
        if(blacklist[121]==1){
           printf("%s",others121);
       }
        if(blacklist[123]==1){
           printf("%s",others123);
       }
        if(blacklist[126]==1){
           printf("%s",others126);
       }
        if(blacklist[127]==1){
           printf("%s",others127);
       }
        if(blacklist[128]==1){
           printf("%s",others128);
       }
        if(blacklist[131]==1){
           printf("%s",others131);
       }
        if(blacklist[132]==1){
           printf("%s",others132);
       }
        if(blacklist[133]==1){
           printf("%s",others133);
       }
        if(blacklist[137]==1){
           printf("%s",others137);
       }
 

        
}



/*
130 VirtualProtect
バーチャルプロテクト

*/
if(blacklist[130]==1){
        printf(UNDER"\nバーチャルプロテクトを施している可能性があります。"RESET);

        num=0;
        sum=1;
        num=blacklist[130];
        printf("%d/%d\n",num,sum);
       if(blacklist[130]==1){
           printf("%s",others130);
       }

}

/*
2 GetVolumeInformation
3 GetVolumeInformationw
警告音やビープ音が出る

*/
if(blacklist[2]==1 | blacklist[3]==1){
        printf(UNDER"\n警告音やビープ音が出る可能性があります。"RESET);

        num=0;
        sum=2;
        num=blacklist[2]+blacklist[3];
        printf("%d/%d\n",num,sum);
       if(blacklist[2]==1){
           printf("%s",get2);
       }
       if(blacklist[3]==1){
           printf("%s",get3);
       }
        
}


/*
25 RegSetValue
40 RegDeleteValue
41 RegDeleteKey
42 RegCreateKey
43 RegCreateKeyExW
44 RegCreateKeyA
45 RegCreateKeyW
46 RegCreateKeyEx
47 RegEnumKey
windowsレジストリに影響を与える

*/
if(blacklist[25]==1 | blacklist[40]==1 | blacklist[41]==1 | blacklist[42]==1 | blacklist[43]==1 | blacklist[44]==1 | blacklist[45]==1 | blacklist[46]==1 | blacklist[47]==1){
        printf(UNDER"\nwindowsレジストリに影響を与える可能性があります。"RESET);

        num=0;
        sum=9;
        num=blacklist[25]+blacklist[40]+blacklist[41]+blacklist[42]+blacklist[43]+blacklist[44]+blacklist[45]+blacklist[46]+blacklist[47];
        printf("%d/%d\n",num,sum);

       if(blacklist[25]==1){
           printf("%s",set25);
       }
        if(blacklist[40]==1){
           printf("%s",regs40);
       }
        if(blacklist[41]==1){
           printf("%s",regs41);
       }
        if(blacklist[42]==1){
           printf("%s",regs42);
       }
        if(blacklist[43]==1){
           printf("%s",regs43);
       }
        if(blacklist[44]==1){
           printf("%s",regs44);
       }
        if(blacklist[45]==1){
           printf("%s",regs45);
       }
        if(blacklist[46]==1){
           printf("%s",regs46);
       }
        if(blacklist[47]==1){
           printf("%s",regs47);
       }
        
}
/*
15 GetLocaleInfo
16 GetLocaleInfoA
17 GetLocaleInfoW
90 ComputerInfo
91 get_Computer
100 get_LocalTime
134 get_exploitable_systems
135 get_domaincontroller
136 GET_USER
実行環境を読み取る

*/
if(blacklist[15]==1 | blacklist[16]==1 | blacklist[17]==1 | blacklist[90]==1 | blacklist[91]==1 | blacklist[100]==1 | blacklist[134]==1 | blacklist[135]==1 | blacklist[136]==1){
        printf(UNDER"\n実行環境を読み取る可能性があります。"RESET);

        num=0;
        sum=9;
        num=blacklist[15]+blacklist[16]+blacklist[17]+blacklist[90]+blacklist[91]+blacklist[100]+blacklist[134]+blacklist[135]+blacklist[136];
        printf("%d/%d\n",num,sum);
       if(blacklist[15]==1){
           printf("%s",get15);
       }
        if(blacklist[16]==1){
           printf("%s",get16);
       }
        if(blacklist[17]==1){
           printf("%s",get17);
       }
        if(blacklist[90]==1){
           printf("%s",computer90);
       }
        if(blacklist[91]==1){
           printf("%s",computer91);
       }
        if(blacklist[100]==1){
           printf("%s",local100);
       }
        if(blacklist[134]==1){
           printf("%s",others134);
       }
        if(blacklist[135]==1){
           printf("%s",others135);
       }
        if(blacklist[136]==1){
           printf("%s",others136);
       }
        
}


        
}

















