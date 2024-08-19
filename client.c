#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <ctype.h>
#include "helper.h"

#define MAXLINE 1024 /* max line size */

char prompt[]="Chatroom> ";
int flag=0;
/*
get the usage of the script
*/
void usage(){
  printf("-h  print help\n");
  printf("-a  IP address of the server[Required]\n");
  printf("-p  port number of the server[Required]\n");
  printf("-u  enter your username[Required]\n");
}


/*
* @brief-: connects the client to ther sever
* NOTE-: THE function traverses the list to find appropriate socket Connection [ is robust]
* @port-: port number
* @hostname-: ip address of the server
* @return -: connection file descriptor
*/

typedef struct client_meta_s {
	int fd;
	SSL_CTX *ctx;
	SSL *ssl;
} client_meta_t;

client_meta_t *connection(char* hostname, char* port){
  int clientfd,rc;
  struct addrinfo hints, *listp, *p;
  SSL_CTX *ctx;
  SSL *ssl;


   // Initialize the SSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create a new SSL context
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM; /* Connections only */
  hints.ai_flags |=AI_ADDRCONFIG;
  hints.ai_flags |= AI_NUMERICSERV; //using fixed port number


  if ((rc = getaddrinfo(hostname, port, &hints, &listp)) != 0) {
    fprintf(stderr,"invalid hostname or port number\n");
    return NULL;
 }

 for (p = listp; p; p = p->ai_next) {
        /* Create a socket descriptor */
        clientfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (clientfd < 0) {
            continue; /* Socket failed, try the next */
        }

        /* Connect to the server */
        if (connect(clientfd, p->ai_addr, p->ai_addrlen) != -1) {
            break; /* Success */
        }

        /* Connect failed, try another */
        if (close(clientfd) < 0) {
            fprintf(stderr, "open_clientfd: close failed: %s\n",
                    strerror(errno));
            return NULL;
        }
    }


    /* Clean up */
    freeaddrinfo(listp);
    if (!p) { /* All connects failed */
            return NULL;
    }
    else { /* The last connect succeeded */
	       // Create a new SSL connection
	    ssl = SSL_new(ctx);
	    if (!ssl) {
		ERR_print_errors_fp(stderr);
		close(clientfd);
		SSL_CTX_free(ctx);
		return NULL;
	    }

	    // Attach the SSL connection to the socket
	    SSL_set_fd(ssl, clientfd);

	    // Perform the SSL/TLS handshake
	    if (SSL_connect(ssl) != 1) {
		ERR_print_errors_fp(stderr);
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		return NULL;
	    }

	    client_meta_t *ret = malloc(sizeof(*ret));
	    ret->fd = clientfd;
	    ret->ctx = ctx;
	    ret->ssl = ssl;
            return ret;
    }
}

// read server response
void* reader(void* var){
  char buf[MAXLINE];
  rio_t rio;
  int status;
  SSL *ssl = (SSL *)var;
  // initialise rio data structure
  rio_readinitb(&rio, ssl);
  while(1){
      // print the Chatroom prompt
      printf("%s",prompt);
      fflush(stdout);
     while((status=rio_readlineb(&rio,buf,MAXLINE)) >0){
          //error
          if(status == -1)
            exit(1);
          if(!strcmp(buf,"\r\n")){
              break;
            }
          // exit from the server
          if (!strcmp(buf,"exit")){
              SSL_free(ssl);
              exit(0);
            }
          if (!strcmp(buf,"start\n")){

               printf("\n");
            }

          else {
		if (!isascii(buf[0])) printf("Hit garbage\n");
             printf("%s",buf);
	 }
      }
      if (status == 0) {
	SSL_free(ssl);
      	printf("\nServer has closed connection.\nExiting....\n");
	exit(1);
      }
  }
}

int main(int argc, char **argv){


  char *address=NULL,*port=NULL,*username=NULL;
  char cmd[MAXLINE];
  char c;
  pthread_t tid;
  //parsing command line arguments
  while((c = getopt(argc, argv, "hu:a:p:u:")) != EOF){
    switch(c){
      // print help
      case 'h':
         usage();
         exit(1);
         break;
      // get server address
      case 'a':
         address=optarg;
         break;
      // get server port number
      case 'p':
         port=optarg;
         break;
      // get the username
      case 'u':
         username=optarg;
         break;

      default:
          usage();
          exit(1);

    }


   }

   if(optind  == 1 || port == NULL || address == NULL || username == NULL){
    printf("Invalid usage\n");
    usage();
    exit(1); }

    client_meta_t *meta = connection(address,port);

    if(!meta){
       printf("Couldn't connect to the server\n");
       exit(1);
    }
    // add a newline
    char *name = malloc(strlen(username)+2);

    sprintf(name,"%s\n",username);

    // send the server , your username
    SSL *ssl = meta->ssl;
    if(rio_writen(ssl, name, strlen(name)) == -1){
       perror("not able to send the data");
       SSL_free(meta->ssl);
       SSL_CTX_free(meta->ctx);
       free(meta);
       exit(1);
    }

    // a thread for reading server response
    pthread_create(&tid,NULL,reader, (void*)ssl);

    while(1){
      // read the command
      if ((fgets(cmd, MAXLINE, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
	    SSL_free(meta->ssl);
	    SSL_CTX_free(meta->ctx);
	    free(meta);
            SSL_free(ssl);
            exit(1);
        }


      // send the request to the server
      if (rio_writen(ssl, cmd, strlen(cmd)) == -1){
          perror("not able to send the data");
	    SSL_free(meta->ssl);
	    SSL_CTX_free(meta->ctx);
	    free(meta);
          exit(1);
        }

    }
}
