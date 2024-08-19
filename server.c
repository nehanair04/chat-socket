#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "helper.h"

//********************GLOBAL DATA_STRUCTURES & CONSTANTS****************************
#define bufsize 2048

// mutex lock for global data access
pthread_mutex_t mutex;

struct client{
    char *name;
    SSL *ssl;
    struct client *next;
};

struct client *header=NULL;

//**********************************************************************************

/*
 * @brief-: add user to the global user DATA_STRUCTURES
 * INSERTION AN HEAD -> O(1) complexity
*/

void add_user(struct client *user){

   if(header == NULL){
     header=user;
     user->next=NULL;
   }
   else{
      user->next=header;

      header=user;
   }
}

void print_disconnect_message(char *username) {
    char message[bufsize];
    sprintf(message, "Client '%s' has disconnected.\n", username);
    printf("%s", message);
}
/*
 * @brief-: delete client from thr global list
 *  O(n) complexity
 */
void delete_user(SSL *ssl){
   struct client *user=header;
   struct client *previous=NULL;
   // identify the user
   while(user->ssl != ssl){
     previous=user;
     user=user->next;
   }

   if(previous == NULL)
      header=user->next;

   else
     previous->next=user->next;

   // free the resources
   free(user->name);
   free(user);

}

/*
* @brief-: assigns a listning socket at a given port number
* NOTE-: THE function traverses the list to find appropriate socket Connection
* for the server [ isrobust]
* @port-: port number
* @return -: listining file descriptor
*/
void *ssl_init() {
    SSL_CTX *ctx;
    SSL *ssl;

    // Initialize the SSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create a new SSL context
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Load the server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}


typedef struct server_metadata {
	int fd;
	SSL_CTX *ctx;
} server_metadata_t;

server_metadata_t* connection(char * port){

   struct addrinfo *p, *listp, hints;
   int rc,listenfd,optval=1;

   SSL_CTX *ctx = ssl_init();
   //initialise to zero
   memset(&hints,0,sizeof(struct addrinfo));
   hints.ai_family = AF_INET;
   hints.ai_socktype = SOCK_STREAM; /* Connections only */
   hints.ai_flags =AI_ADDRCONFIG|AI_PASSIVE;
   hints.ai_flags |= AI_NUMERICSERV; //using fixed port number


   if ((rc = getaddrinfo(INADDR_ANY, port, &hints, &listp)) != 0) {
     fprintf(stderr,"get_address info failed port number %s is invalid\n",port);
     return NULL;
  }

   // traverse the list of available Connections
   for (p = listp; p; p = p->ai_next) {

       listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
       if (listenfd < 0) {
         continue; /* Socket failed, try the next */
       }

       /* Eliminates "Address already in use" error from bind */
      setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,sizeof(int));
      //bind the socket, returns 0 on Success
      if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0) {
          break; /* Success */
      }
      if (close(listenfd) < 0) { /* Bind failed, try the next */
            fprintf(stderr, "open_listenfd close failed: %s\n",
                    strerror(errno));
            return NULL;
        }

    }

    // avoiding memory leak
    freeaddrinfo(listp);
    if (!p) { /* All connects failed */
        return NULL;
    }

    // setting backlog to 1024 , desired value
    // set the socket to listen
    if (listen(listenfd, 1024) < 0) {
            close(listenfd);
            return NULL;
    }

    server_metadata_t *ret = malloc(sizeof(server_metadata_t));
    ret->fd = listenfd;
    ret->ctx = ctx;

    return ret;
}

/*
 * send msg to all the clients
 */
void send_msg(SSL *ssl,char* msg, char* receiver, char* sender){

    char response[bufsize];
    struct client *user=header;
    if(receiver == NULL || (*receiver == '\0')) {
     while (user != NULL){
      if (user->ssl == ssl){
         strcpy(response,"msg sent\n\r\n");
         rio_writen(user->ssl,response,strlen(response));
      } else{
         sprintf(response,"start\n%s:%s\n\r\n",sender,msg);
         rio_writen(user->ssl, response,strlen(response));
      }
      user=user->next;
    }
   } else{
       while (user != NULL){
         if(!strcmp(user->name,receiver)){
           sprintf(response,"start\n%s:%s\n\r\n",sender,msg);
           rio_writen(user->ssl, response,strlen(response));
           strcpy(response,"msg sent\n\r\n");
           rio_writen(ssl, response,strlen(response));
           return;
         }
         user=user->next;
       }
        strcpy(response,"user not found\n\r\n");
        rio_writen(ssl, response,strlen(response));

   }
}

void evaluate(char *buf ,SSL *ssl, char *username){

  char response[bufsize];
  char msg[bufsize];
  char receiver[bufsize];
  char keyword[bufsize];
  // clear the buffer
  msg[0]='\0';
  receiver[0]='\0';
  keyword[0]='\0';
  response[0]='\0';
  struct client *user=header;


  if(!strcmp(buf,"help")){
        sprintf(response,"msg \"text\" : send the msg to all the clients online\n");
        sprintf(response,"%smsg \"text\" user :send the msg to a particular client\n",response);
        sprintf(response,"%sonline : get the username of all the clients online\n",response);
        sprintf(response,"%squit : exit the chatroom\n\r\n",response);
        rio_writen(ssl,response,strlen(response));
        return;
   }
   // get the online user name
   if (!strcmp(buf,"online")){
        // empty the buffer
        response[0]='\0';
        //global access should be exclusive
        pthread_mutex_lock(&mutex);
        while(user!=NULL){
        sprintf(response,"%s%s\n",response,user->name);
        user=user->next;

        }
    sprintf(response,"%s\r\n",response);
    //global access should be exclusive
    pthread_mutex_unlock(&mutex);
    rio_writen(ssl,response,strlen(response));
    return;
   }

   if (!strcmp(buf,"quit")){
      pthread_mutex_lock(&mutex);
      delete_user(ssl);
      pthread_mutex_unlock(&mutex);
      strcpy(response,"Exiting...");
      rio_writen(ssl,response,strlen(response));

      // Shutdown the SSL connection and close the socket.
      int sfd = SSL_get_fd(ssl);
      SSL_shutdown(ssl);
      close(sfd);

      print_disconnect_message(username);

      return;

   }

   sscanf(buf,"%s \" %[^\"] \"%s",keyword,msg,receiver);

   if (!strcmp(keyword,"msg")){

        pthread_mutex_lock(&mutex);
        send_msg(ssl, msg, receiver, username);
        pthread_mutex_unlock(&mutex);
   }
  else {
	 if (keyword[0] == '\0') {
		 strcpy(response, "\r\n");
	} else {
	     strcpy(response,"Invalid command\n\r\n");
	}
     rio_writen(ssl,response,strlen(response));

  }

}
/*
* @brief-: the function handles incoming clients concurrently
* @vargp-: poiner to the connection file descriptor
*/
void* client_handler(void *vargp ){

  char username[bufsize];
  rio_t rio;
  struct client *user;
  long byte_size;
  char buf[bufsize];
  // detaching the thread from peers
  // so it no longer needs to be
  // terminated in the main thread
   pthread_detach(pthread_self());

   // saving the connection fd on function stack
   SSL *ssl = *(SSL **)vargp;
   rio_readinitb(&rio, ssl);

    // read the user name as a single line , -1 is for error handling
    if( (byte_size=rio_readlineb(&rio,username,bufsize)) == -1){
         SSL_free(ssl);
         return NULL;
    }
    //strip the newline from the string
    username[byte_size-1]='\0';

    int duplicate = 0;
    pthread_mutex_lock(&mutex);
    struct client *temp = header;
    while (temp != NULL) {
        if (strcmp(temp->name, username) == 0) {
            duplicate = 1;
            break;
        }
        temp = temp->next;
    }
    pthread_mutex_unlock(&mutex);

    if (duplicate) {
        char response[bufsize];
        strcpy(response, "Username already taken. Please enter a different username.\r\n");
        rio_writen(ssl, response, strlen(response));
        int sfd = SSL_get_fd(ssl);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sfd);

        print_disconnect_message(username);

        return NULL;
    }

    // assign space in the global structure
    user=malloc(sizeof(struct client));
    // error handling
    if (user == NULL){
      perror("memory can't be assigned");
      SSL_free(ssl);
      return NULL;
    }
    // user->name=username is not safe
    // as the local stack can be accessed by peer threads
    // assign space in heap
    user->name=malloc(sizeof(username));
    memcpy(user->name,username,strlen(username)+1);
    user->ssl = ssl;

    //lock
    pthread_mutex_lock(&mutex);
    add_user(user);
    //unlock
    pthread_mutex_unlock(&mutex);

    // read client response
    while((byte_size=rio_readlineb(&rio,buf,bufsize)) >0){

        //strip the newline from the string
        buf[byte_size-1]='\0';
        // take appropriate action
        evaluate(buf,ssl,username);

    }
    SSL_free(ssl);

    return NULL;
}


int main(int argc,char **argv){
  struct sockaddr_storage clientaddr;
  socklen_t clientlen;
  char host[1000];
  char *port="80";
  int confd;
  pthread_t tid;
  SSL *ssl;

  if (argc > 1)
    port = argv[1];

  // make a connection file descriptor
  server_metadata_t *meta = connection(port);

  //connection failed
  if(!meta) {
   printf("connection failed\n");
   exit(1);
  }

  printf("waiting at port '%s' \n",port);

  // loop to keep accepting clients
  while(1){
      // assign space in the heap [prevents data race]
      confd = accept(meta->fd, (struct sockaddr *)&clientaddr, &clientlen);
      printf("A new client is online\n");
      // Create a new SSL connection

        ssl = SSL_new(meta->ctx);
        if (!ssl) {
            ERR_print_errors_fp(stderr);
            close(confd);
            continue;
        }

        // Attach the SSL connection to the client socket
        SSL_set_fd(ssl, confd);

        // Perform the SSL/TLS handshake
        if (SSL_accept(ssl) != 1) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            continue;
        }

      // assign a seperate thread to deal with the new client
       pthread_create(&tid,NULL,client_handler, (void *)&ssl);
  }
  SSL_CTX_free(meta->ctx);

}
