//Robert Pierucci
//Honeynet Log Analyzer
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <string.h>
using namespace std;

char log[] = "honeynet-Feb1_FebXX.log";
char ipLog[] = "ipLog.txt";


struct ListNode {
    char data[18];
    ListNode* next;
};

ListNode *createNode(char *elem);
ListNode *listInsert(ListNode* head, ListNode* prev, char *elem);
bool listSearch(ListNode* head, char *elem);
void listDeallocate(ListNode* head);
void listCount(ListNode* head);
void analyzeLog(ifstream &fin, ofstream &fout);
void searchLog(char *ip, ifstream &fin, ofstream &fout);

int main () {
    
    char ip[18];

    cout << "Honeynet Log Analzyer\n";
    cout << "Please wait a moment, analyzing logfile...\n";
    ifstream fin(log);
        if (fin.fail()) {
            cout << "Error opening log file **" << log << "**" << endl;
            exit(1);
        }
    ofstream fout(ipLog);
    analyzeLog(fin, fout);

    cout << "Please enter an I.P. to search the log file for:";
    cin.getline(ip, 18);
    cout << "Searching for IP address " << ip << " in logfile..." << endl;
    searchLog(ip, fin, fout);
    cout << "Search complete. View " << ipLog << " for a summary." << endl;
    fin.close();
    fout.close();
    return 0;
}

void analyzeLog(ifstream &fin, ofstream &fout) { 
	//Reads Honeynet log using linked list to count unique SRC IPs
	//Format: "Feb  1 00:00:02 bridge kernel: INBOUND TCP: IN=br0 PHYSIN=eth0 OUT=br0 PHYSOUT=eth1 SRC=192.150.249.87 DST=11.11.11.84 LEN=40 TOS=0x00 PREC=0x00 TTL=110 ID=12973 PROTO=TCP SPT=220 DPT=6129 WINDOW=16384 RES=0x00 SYN URGP=0"

	//line: holds each line
	//first: first date and time accessed
	//last: last date and time accessed
	//ipwrite: holds ip to place in a linked list
	//token: tokenated string
	//src: "SRC=" with IP attached
    char line[250], first[16], last[16], ipwrite[16], *token, *src;

	//count: number of total lines
	//pos: beginning of current line
	//posnext: beginning of next line
    int count = 0, pos = 0, posnext = 0;

	//linked list
    ListNode* head = NULL,  *prev = NULL;

    cout << "Reading " << log << "..." << endl;
    
    while(fin.getline(line, 250)){
		//if first line, first time and date accessed
        if (count == 0) {
            memcpy(first, line, 15);
        }
        token = strtok(line, " ");
            while (token != NULL) {
                src = strstr(token, "SRC=");
                    if (src != NULL) {
                        memcpy(ipwrite, token + 4, 15);
						//if the list is empty or the ip is not in the list currently, insert it
                        if (head == NULL || (listSearch(head, ipwrite) == false)) {
                            head = listInsert(head, prev, ipwrite);
                        }
                        else {
							//do nothing, ip already in list
                        }
                    }
                token = strtok (NULL, " ");
            }
		//set some file pointer positions
		//first pass, both 0, posnext will be the next line
        pos = posnext;
		//posnext is where filepointer ended up after line read
        posnext = fin.tellg();
		//increment total count of IPs in log
        count++;   
    }
	//last line so reread and place into the last access position, put the file pointer back at the beginning of the line then read it again
	fin.clear();
    fin.seekg(pos);
    fin.getline(line, 250);
    memcpy(last, line, 15);

	//count unique list items
    listCount(head);

	//garbage collection
    listDeallocate(head);

    cout << "The logfile " << log << " is " << count << " lines long." << endl;
    cout << "Time first accessed: **" << first << "**" << endl;
    cout << "Time last accessed:  **" << last << "**" << endl;

    fout << "IP Log Analysis" << endl;
    fout << "Time server first accessed: **" << first << "**" << endl;
    fout << "Time server last accessed:  **" << last << "**" << endl;
    fout << endl;
}

void listCount(ListNode* head) {
	ListNode* ptr = head;
	int count = 0;
	while (ptr) {
		count++;
		ptr = ptr->next;
	}

	cout << "There are " << count << " unique IP addresses in this logfile." << endl;
}

void searchLog(char *ip, ifstream &fin, ofstream &fout) {
	//searches log for user defined IP address in SRC column
	//line holds full line, searchterm holds "SRC="+ ip address of search, date holds the date and time of access, token holds tokenated string
    char line[250], searchterm[25] = "SRC=", date[16], *token;

	//position is the end of each line so the file pointer 
    int count = 0;
    
    fout << "At the following times the log received interaction from IP " << ip << endl << endl;
    
    strncpy(searchterm + 4, ip, 21); 
    while (fin.getline(line,250)){ 
		//grabs date which is first 15 characters of the line
        memcpy(date, line, 15);
		//tokenize the rest of the line
        token = strtok(line, " ");
        while (token != NULL) {
			//if token matches searchterm, we have a match. Write the date in the iplog.txt
            if (strcmp(token, searchterm) == 0) {
                fout << date << endl;
                count++;
            }
            token = strtok (NULL, " ");
        }
    } 
    cout << "IP address " << ip << " was found in log " << count << " times." << endl;
    fout << endl << "IP address " << ip << " was found in log " << count << " times." << endl;
}


/***********/

ListNode* createNode(char* elem){
    ListNode* temp = NULL;
        try{
            temp = new ListNode;
        }catch(bad_alloc){
            temp = NULL;
        }
        if (temp==NULL) {
            cout << "Allocation Failed\n";
            exit (1);
        }
        strcpy(temp->data, elem);
        temp->next = NULL;
        return (temp);
}

ListNode* listInsert(ListNode *head, ListNode *prev, char* elem){

    ListNode* newNode = NULL;
    ListNode* tmp = head;

    if (prev != NULL){
        bool inList = false;
        while (tmp){
            if (prev == tmp){
                inList = true;
                break;
            }
            tmp = tmp->next;
        }
        if (inList == false){
            cout << "Invalid Previous Address";
            return (head);
        }
    }

    if (prev == NULL){
        newNode = createNode(elem);
        if (newNode == NULL){
            return (head);
        }

        newNode->next = head;
        return(newNode);
    }
    else{
        newNode = createNode(elem);
        if (newNode == NULL){
            return(head);
        }
        newNode->next = prev->next;
/*        prev->next = newNode; */
        return(head);
    }
}

void listDeallocate(ListNode* head){
    ListNode* ptr=head, *temp=NULL;
    while (ptr!=NULL){
        temp = ptr;
        ptr=ptr->next;
        delete temp;
    }
}

bool listSearch(ListNode* head, char* elem){
    ListNode* ptr = head;
    while (ptr) {
        if(strcmp(ptr->data, elem) == 0) {
            return(true);
        }
        ptr=ptr->next;
    }

    return(false);
}

