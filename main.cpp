

#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <sstream>
#include <sys/time.h>

#include <algorithm>    // std::max


#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

 

#define _SVID_SOURCE
#include <netdb.h>

#include <crypt.h>
 

#include <zlib.h>

#include <sys/types.h>
#include <sys/ioctl.h>

#include <bitset>

 


//https://www.cryptopp.com/
#include "../Crypto/cmac.h"

#include "../Crypto/osrng.h"
#include "../Crypto/secblock.h"
#include "../Crypto/hex.h"
#include "../Crypto/modes.h"
#include "../Crypto/aes.h"
#include "../Crypto/sha.h"


 





int socket_desc;    
struct sockaddr_in server;  

//glowna petla serwera..
pthread_t thread;


int goClose;



 

struct str_card
{
    char card[43];
};
 

 
//------------------------------------------------------------
//-----------------------------------------------------------

//http://artjomb.github.io/cryptojs-extension/
void createCMAC(const char* ciag, const char* klucz, int rozmiar_ciagu, int rozmiar_klucza, char* cmacBuff, int* sizeCmac)
{
    
   // http://artjomb.github.io/cryptojs-extension/
    
    
   CryptoPP::AutoSeededRandomPool prng;

  /// CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
  // prng.GenerateBlock(key, key.size());
      
   
   //std::string stKey = std::string(klucz);
   CryptoPP::SecByteBlock key( (const unsigned char*)klucz, rozmiar_klucza ) ;   
    
   
  // std::string plain = std::string(ciag) ;  //"CMAC Test";
   std::string mac, encoded;

   /*********************************\
   \*********************************/

   // Pretty print key
    encoded.clear();
    CryptoPP::StringSource ss1(key, key.size(), true,
      new CryptoPP::HexEncoder(
         new CryptoPP::StringSink(encoded)
       ) // HexEncoder
     ); // StringSource

    //std::cout << "\nkey: " << encoded << std::endl;
   // std::cout << "\nplain text: " << plain << std::endl;

/*********************************\
\*********************************/
    
    
    /*********************************\
\*********************************/

   try
  {
    CryptoPP::CMAC<CryptoPP::AES> cmac(key.data(), key.size());

    CryptoPP::SecByteBlock b3(ciag, rozmiar_ciagu );
    
    CryptoPP::StringSource ss2(b3,b3.size(), true, 
        new CryptoPP::HashFilter(cmac,
            new CryptoPP::StringSink(mac)
        ) // HashFilter      
    ); // StringSource
   }
   catch(const CryptoPP::Exception& e)
   {
      std::cerr << e.what() << std::endl;
      exit(1);
   }



  
  memcpy(cmacBuff, mac.c_str(), mac.size() );
  *sizeCmac = mac.size();
  
 
    
    
    // Pretty print
encoded.clear();
CryptoPP::StringSource ss3(mac, true,
    new CryptoPP::HexEncoder(
        new CryptoPP::StringSink(encoded)
    ) // HexEncoder
); // StringSource

//std::cout << "\nXXXXXcmac: " << encoded << std::endl;
    

}


//-----------------------------------------------------------
//https://www.cryptopp.com/wiki/Advanced_Encryption_Standard
//http://aes.online-domain-tools.com/
void aes256(const char* ciag, const char* klucz, int rozmiar_ciagu, int rozmiar_klucza, char* outBuff)
{
    
      CryptoPP::AutoSeededRandomPool rnd;
    
      CryptoPP::SecByteBlock key( (const unsigned char*)klucz, rozmiar_klucza ) ;  
    
      CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
      rnd.GenerateBlock(iv, iv.size());
      
      //CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, key.size(), iv);
      //CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, key.size());
      CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, key.size());
      cfbEncryption.ProcessData(outBuff, ciag, rozmiar_ciagu);
    
}


void aes128Encrypt(const char* ciag, const char* klucz, int rozmiar_ciagu, int rozmiar_klucza, char* outBuff, char* block, int blockSize)
{
    
      CryptoPP::AutoSeededRandomPool rnd;
    
      CryptoPP::SecByteBlock key( (const unsigned char*)klucz, rozmiar_klucza ) ;  
    
      
       CryptoPP::SecByteBlock iv( (const unsigned char*)block, blockSize ) ;  
      //CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
      //rnd.GenerateBlock(iv, iv.size());
      
      //CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, key.size(), iv);
      //CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, key.size());
      
      CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, key.size(),iv);
      cfbEncryption.ProcessData(outBuff, ciag, rozmiar_ciagu);    
}


void aes128Decrypt(const char* ciag, const char* klucz, int rozmiar_ciagu, int rozmiar_klucza, char* outBuff,  char* block, int blockSize)
{
    
      CryptoPP::AutoSeededRandomPool rnd;
    
      CryptoPP::SecByteBlock key( (const unsigned char*)klucz, rozmiar_klucza ) ;  
    
     // CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
     // rnd.GenerateBlock(iv, iv.size());
      
      CryptoPP::SecByteBlock iv( (const unsigned char*)block, blockSize ) ; 
      
      //CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, key.size(), iv);
      //CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, key.size());
      CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption ctrDecryption(key, key.size(), iv);
      ctrDecryption.ProcessData(outBuff, ciag, rozmiar_ciagu);    
}


void aes256Encrypt(const char* ciag, const char* klucz, int rozmiar_ciagu, int rozmiar_klucza, char* outBuff, char* block, int blockSize)
{
    
      CryptoPP::AutoSeededRandomPool rnd;
    
      CryptoPP::SecByteBlock key( (const unsigned char*)klucz, rozmiar_klucza ) ;  
    
      
       CryptoPP::SecByteBlock iv( (const unsigned char*)block, blockSize ) ;  
      //CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
      //rnd.GenerateBlock(iv, iv.size());
      
      //CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, key.size(), iv);
      //CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, key.size());
      
      CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, key.size(),iv); //AES::MAX_KEYLENGTH klucz 32
      cfbEncryption.ProcessData(outBuff, ciag, rozmiar_ciagu);    
}


void aes256Decrypt(const char* ciag, const char* klucz, int rozmiar_ciagu, int rozmiar_klucza, char* outBuff,  char* block, int blockSize)
{
    
      CryptoPP::AutoSeededRandomPool rnd;
    
      CryptoPP::SecByteBlock key( (const unsigned char*)klucz, rozmiar_klucza ) ;  
    
     // CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
     // rnd.GenerateBlock(iv, iv.size());
      
      CryptoPP::SecByteBlock iv( (const unsigned char*)block, blockSize ) ; 
      
      //CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, key.size(), iv);
      //CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, key.size());
      CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption ctrDecryption(key, key.size(), iv); //AES::MAX_KEYLENGTH klucz 32
      ctrDecryption.ProcessData(outBuff, ciag, rozmiar_ciagu);    
}


//-----------------------------------------------------------
//https://cryptii.com/pipes/hash-function
void SHA256(char* input, unsigned int sizeInput, char* output, int* sizeOutput)
{
  CryptoPP::byte const* pbData = input; //(CryptoPP::byte*)data.data();
  unsigned int nDataLen =  sizeInput; //data.length();
  CryptoPP::byte abDigest[CryptoPP::SHA256::DIGESTSIZE];

  CryptoPP::SHA256().CalculateDigest(abDigest, pbData, nDataLen);

  // return string((char*)abDigest);  -- BAD!!!
  //return std::string((char*)abDigest, CryptoPP::SHA256::DIGESTSIZE);
  
  memcpy(output, (char*)abDigest, CryptoPP::SHA256::DIGESTSIZE );
  *sizeOutput = CryptoPP::SHA256::DIGESTSIZE;
  
}

//------------------------------------------------------------
//https://crccalc.com/
struct crc32
{
	static void generate_table(uint32_t(&table)[256])
	{
		uint32_t polynomial = 0xEDB88320;
		for (uint32_t i = 0; i < 256; i++) 
		{
			uint32_t c = i;
			for (size_t j = 0; j < 8; j++) 
			{
				if (c & 1) {
					c = polynomial ^ (c >> 1);
				}
				else {
					c >>= 1;
				}
			}
			table[i] = c;
		}
	}

	static uint32_t update(uint32_t (&table)[256], uint32_t initial, const void* buf, size_t len)
	{
		uint32_t c = initial ^ 0xFFFFFFFF;
		const uint8_t* u = static_cast<const uint8_t*>(buf);
		for (size_t i = 0; i < len; ++i) 
		{
			c = table[(c ^ u[i]) & 0xFF] ^ (c >> 8);
		}
		return c ^ 0xFFFFFFFF;
	}
};


//https://crccalc.com/
unsigned int crc32b(unsigned char *message, unsigned int l)
{
   unsigned int i, j;
   unsigned int crc, msb;

   crc = 0xFFFFFFFF;
   for(i = 0; i < l; i++) {
      // xor next byte to upper bits of crc
      crc ^= (((unsigned int)message[i])<<24);
      for (j = 0; j < 8; j++) {    // Do eight times.
            msb = crc>>31;
            crc <<= 1;
            crc ^= (0 - msb) & 0x04C11DB7;
      }
   }
   return crc;         // don't complement crc on output
}

//------------------------------------------------------------

std::string gxh_IntToString(int value)
{
     std::string Result;         
     std::ostringstream convert;   
     convert << value; 
     Result = convert.str(); 
    
     char * data = new char[Result.size() + 1];
     std::copy(Result.begin(), Result.end(), data);
     data[Result.size()] = '\0'; 
     
     std::string ret = std::string(data);
     delete[] data;
     
     return ret;
};

std::string gxh_LongToString(unsigned long value)
{
     std::string Result;         
     std::ostringstream convert;   
     convert << value; 
     Result = convert.str(); 
    
     char * data = new char[Result.size() + 1];
     std::copy(Result.begin(), Result.end(), data);
     data[Result.size()] = '\0'; 
     
     std::string ret = std::string(data);
     delete[] data;
     
     return ret;
};

//------------------------------------------------------------
//------------------------------------------------------------

/**
 * Funcja zwraca liste kart
 * @param Install numer instalacji w placowce
 * @param cardOut wskaznik do listy kard
 * @param countCardOut ilosc zwroconych
 * @param sygOut sygnatura
 */
bool get_syg( unsigned long Install, str_card* cardOut, int* countCardOut, unsigned long* sygOut, unsigned long* sygObj, int* outCountObj)
{
          *countCardOut = 0; //jesli nie uda sie pobrać...
          *outCountObj = 0;
      
          
          std::string POST = "";
          POST.append("POST ");
          POST.append("/reader");
          POST.append(" HTTP/1.0\r\n");
          
          POST.append("Host: ");
          POST.append("mm.edu.pl");
          POST.append("\r\n");
          
          POST.append("User-Agent: ");
          POST.append("mm web plugin/1.0 Błażej Kita ");
          POST.append("\r\n");
          
          POST.append("Content-Type: ");
          POST.append("application/x-www-form-urlencoded");
          POST.append("\r\n");
          
          
          std::string strInstall = gxh_LongToString(Install);
          
          POST.append("Content-Length: ");
          POST.append( gxh_IntToString( strInstall.length() + 8 ) ); // + ramka=
          POST.append("\r\n");
          
          POST.append("\r\n");     
          POST.append("install=");
          POST.append( strInstall );
          
          
          std::cout<<"Wysylam dane do serwera: "<<POST.c_str()<<"\n\n";
          
          
          
          std::string URL = "mm.edu.pl" ;
          
          /* first what are we going to send and where are we going to send it? */
          int portno =        80;
          const char *host =        URL.c_str();
          const char *message_fmt = POST.c_str();  // "POST /apikey=%s&command=%s HTTP/1.0\r\n\r\n";

          struct hostent *serverx;
          struct sockaddr_in serv_addr;
          int sockfd, bytes, sent, received, total;
          char message[40096],response_serv[40096];
        

          /* fill in the parameters */      
          memcpy(message, message_fmt, strlen(message_fmt));

          /* create the socket */
         sockfd = socket(AF_INET, SOCK_STREAM, 0);
         if (sockfd < 0)
         {                        
             std::cout<<"error opening socket\n";
             return;
         }

          /* lookup the ip address */
         serverx = gethostbyname(host);
         if (serverx == NULL)
         {     
              close(sockfd);
              std::cout<<"not such host\n";
              return;
         }

         /* fill in the structure */
         memset(&serv_addr,0,sizeof(serv_addr));
         serv_addr.sin_family = AF_INET;
         serv_addr.sin_port = htons(portno);
         memcpy(&serv_addr.sin_addr.s_addr,serverx->h_addr,serverx->h_length);

         /* connect the socket */
         if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
         {
               std::cout<<"error connection\n";
               close(sockfd);
               return;
         }

         
         //--setTimeOut-------------------------
         struct timeval tv;
         fd_set fdset;
         FD_ZERO(&fdset);
         FD_SET(sockfd, &fdset);
         tv.tv_sec = 3;             /* 3 second timeout */
         tv.tv_usec = 0;

         if (select(sockfd + 1, NULL, &fdset, NULL, &tv) == 1)
         {
           int so_error;
           socklen_t len = sizeof so_error;
           getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
         }         
         //------------------------------------- 
         
         /* send the request */
         total = strlen(message);
         sent = 0;
         do 
         {
          bytes = write(sockfd,message+sent,total-sent);
           if (bytes < 0)
           {      
               std::cout<<"ERROR writing message to socket\n";
           }
            if (bytes == 0)
            {
             break;
            }
             sent+=bytes;
         } while (sent < total);
         
         
         //dane walssciy
       //  write(sockfd,dataIn,cIn);

         
        /* receive the response */
        memset(response_serv,0,sizeof(response_serv));
        total = sizeof(response_serv)-1;
        received = 0;
        do {
           bytes = read(sockfd,response_serv+received,total-received);
           if (bytes < 0)
           {              
               std::cout<<"ERROR reading response from socket\n";
           }
           if (bytes == 0)
              break;
           received+=bytes;
           } while (received < total);

        if (received == total)
        {            
            std::cout<<"ERROR storing complete response from socket\n";
        }

        
        close(sockfd);
        
        
        std::cout<<"Dane odebrane ("<<received<<")\n"<<response_serv;
        
        int indexStart = -1;
        
        for(int m=4; m<received; m++)
        {
            if(response_serv[m-4] == 13 && response_serv[m-3] == 10 && response_serv[m-2] == 13 && response_serv[m-1] ==10)
            {
                indexStart = m;
                break;
            }
        }
        
       
        char c1 = 0;
        char c2 = 0;
        
        memcpy(&c1, response_serv + indexStart ,1 ); 
        memcpy(&c2, response_serv + indexStart+1 ,1 ); 
        
        std::cout<<"\nKontrol "<<c1<<"|"<<c2<<"|";
        
        if(c1 !='@' | c2 != '#')
        {
            std::cout<<"\n!!! Nie mozna odczytaj kart";
            return false; //nie mozna odczytaj sygnatur
        }
        
        
       // std::cout<<"\nDane: ";
      //  for(int k=indexStart; k< received; k++)
       // {
       //       printf("%02x",   (int)((unsigned char)response_serv[k]) );           
       //       std::cout<<" ";
       // }
        
        
        
        unsigned long iloscKard  = 0;
        memcpy(&iloscKard, response_serv + indexStart +2 ,4 );

        std::cout<<"\nIlosc kart: "<<iloscKard;
        
        unsigned long iloscObj  = 0;
        memcpy(&iloscObj, response_serv + indexStart +6 ,4 );
        
        std::cout<<"\nIlosc obj: "<<iloscObj;
        
        unsigned long sygnatura = 0;
        memcpy(&sygnatura,   response_serv + indexStart + 10, 4);                        
        
        std::cout<<"\nSygnatura: "<<sygnatura;
 
         
        int indeX = 0;
        for(int w=0; w<255;w++)
        {          
            memcpy( &sygObj[w],  response_serv +  indexStart + 14 + indeX  , 4) ;            
            
            if(sygObj[w] >0) std::cout<<"\nSyg obj "<<w<<": "<<sygObj[w];            
            
            indeX += 4;
        }
        
        
        
        
        //str_card* cardOut, int* countCardOut, unsigned long* sygOut
         *countCardOut = iloscKard;
         *sygOut = sygnatura;
         *outCountObj = iloscObj;
         
 
       
        for(int k=0; k< iloscKard; k++)
        {
            int offset = 43 * k;
            
            char karta[43];       
            memcpy(karta,  response_serv +  indexStart + 1034  + offset, 43 );     // 255 * 4 + 14 poczatekowe..
            
           // std::cout<<"\nKarta "<<(k+1)<<": ";  
           // for(int m=0; m<43; m++)
           // {
            //   printf("%02x",   (int)((unsigned char)karta[m]) );           
            //   std::cout<<" ";
            //}   
            
            memcpy( cardOut[k+1].card, karta,43 ); //pierwszy indeks w kartach to 0
        }
 
      
        
        return true;
   
}




/**
 * 
 * @param Install
 * @param dane
 * @param ilosc_danych
 * @return 
 */
bool register_card( unsigned long Install, char* dane, int ilosc_danych)
{
          
      
          
          std::string POST = "";
          POST.append("POST ");
          POST.append("/reader");
          POST.append(" HTTP/1.0\r\n");
          
          POST.append("Host: ");
          POST.append("mm.edu.pl");
          POST.append("\r\n");
          
          POST.append("User-Agent: ");
          POST.append("mm web plugin/1.0 Błażej Kita ");
          POST.append("\r\n");
          
          POST.append("Content-Type: ");
          POST.append("application/x-www-form-urlencoded");
          POST.append("\r\n");
          
          //dane do wylania...
                       
             std::string dataContent = "";
       
          
             std::string strInstall = gxh_LongToString(Install);                          
             int iloscKart = ilosc_danych / 12;
             
             dataContent.append("install=");
             dataContent.append( strInstall );                          
             
           
             std::cout<<"\nOdczytano kart: "<<iloscKart;
             
             for(int p=0; p<iloscKart; p++)
             {
                 int index = p * 12;
                 
                 char karta[12];
                 memset(karta,0,12);
                 memcpy(karta, dane + index, 12);
                 
                 unsigned long  rTime   = 0;
                 unsigned short rDoorNr = 0;
                 unsigned short rTyp    = 0;
                 unsigned long  rUser   = 0;
                 
                 memcpy(&rTime, karta, 4);
                 memcpy(&rDoorNr, karta+4, 2);
                 memcpy(&rTyp, karta+6, 2);
                 memcpy(&rUser, karta+8, 4);
                 
                 
                // Frame: Time 2d 90 8c 5d  Dor  ff ff   Typ 81 00   User  0c 00 70 00
                 std::cout<<"\n\nRejestracja karty: "<<(int)rTyp<<"\n-------------------------------------------------------------\n";
                 
                 int operacja = 100; // 100 = nie wiadomoo I O
                 if((int)rTyp == 129)                            
                 {
                     operacja = 0; //wyjscie - najmłodszy bit określa kierunke.
                 }else
                 if((int)rTyp == 128 )          
                 {
                       operacja = 1; //wejscie - najmłodszy bit określa kierunke. 0 - wejście
                 }
                 else operacja = 2; 
                 
                           //0b0000000010000001
                 
                 std::cout<<"\nKartaFrame: ";          
                 for(int m=0; m<12; m++)
                 {
                    printf("%02x",   (int)((unsigned char)karta[m] ) );            
                    std::cout<<" ";
                 } 
                 
                 
                 
                 //
                 unsigned long KartaId      = rUser >> 20;    // 12 najstarszych bitów do id karty z bazy danych..
                 unsigned long PowiazanieId = rUser & 0b00000000000011111111111111111111; //20 najmłodszych bitó to id relacji w bazie danych tabeli hashujacej..
                                
                 
                  std::cout<<"\nKarta UserID: "<<rUser<<" , KartaId: "<<KartaId<<", PowiazanieId: "<<PowiazanieId<<" ";
                 
                 dataContent.append("&cards[");
                 dataContent.append(gxh_IntToString(p) );
                 dataContent.append( "][user][all]=" ); //
                 dataContent.append( gxh_LongToString(rUser) ); //
                 
                 dataContent.append("&cards[");
                 dataContent.append(gxh_IntToString(p) );
                 dataContent.append( "][user][p_karty_zblizeniowe_id]=" ); //
                 dataContent.append( gxh_LongToString(KartaId) ); //
                 
                 dataContent.append("&cards[");
                 dataContent.append(gxh_IntToString(p) );
                 dataContent.append( "][user][p_karty_zblizeniowe_dzieci_id]=" ); //
                 dataContent.append( gxh_LongToString(PowiazanieId) ); //
               
                 dataContent.append("&cards[");
                 dataContent.append(gxh_IntToString(p) );
                 dataContent.append( "][time]=" ); //
                 dataContent.append( gxh_LongToString(rTime) ); //
                 
                 dataContent.append("&cards[");
                 dataContent.append(gxh_IntToString(p) );
                 dataContent.append( "][operacja]=" ); //
                 dataContent.append( gxh_IntToString(operacja) ); //
                 
                 
                std::cout<<"\nrUser: "<<rUser;
                std::cout<<"\nrTime: "<<rTime;
                std::cout<<"\nPost: "<<dataContent.c_str();
                 
                 // [Rej]12 =  [Time]4, [DorrNr]2, [Typ]2, [User]4
             }
             
          
             
          POST.append("Content-Length: ");
          POST.append( gxh_IntToString( dataContent.length()  ) ); // + ramka=
          POST.append("\r\n");
          
          POST.append("\r\n");     
          POST.append(dataContent);
          
          
          std::cout<<"Wysylam dane do serwera: "<<POST.c_str()<<"\n\n";
          
          
          
          std::string URL = "mm.edu.pl" ;
          
          /* first what are we going to send and where are we going to send it? */
          int portno =        80;
          const char *host =        URL.c_str();
          const char *message_fmt = POST.c_str();  // "POST /apikey=%s&command=%s HTTP/1.0\r\n\r\n";

          struct hostent *serverx;
          struct sockaddr_in serv_addr;
          int sockfd, bytes, sent, received, total;
          char message[4096],response_serv[4096];
        

          /* fill in the parameters */      
          memcpy(message, message_fmt, strlen(message_fmt));

          /* create the socket */
         sockfd = socket(AF_INET, SOCK_STREAM, 0);
         if (sockfd < 0)
         {                        
             std::cout<<"error opening socket\n";
             return;
         }

          /* lookup the ip address */
         serverx = gethostbyname(host);
         if (serverx == NULL)
         {     
              close(sockfd);
              std::cout<<"not such host\n";
              return;
         }

         /* fill in the structure */
         memset(&serv_addr,0,sizeof(serv_addr));
         serv_addr.sin_family = AF_INET;
         serv_addr.sin_port = htons(portno);
         
         memcpy(&serv_addr.sin_addr.s_addr,serverx->h_addr,serverx->h_length);
         //serv_addr.sin_addr.s_addr = inet_addr("89.161.252.165");

         /* connect the socket */
         if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
         {
               std::cout<<"error connection\n";
               close(sockfd);
               return false;
         }

         
          //--setTimeOut-------------------------
         struct timeval tv;
         fd_set fdset;
         FD_ZERO(&fdset);
         FD_SET(sockfd, &fdset);
         tv.tv_sec = 3;             /* 3 second timeout */
         tv.tv_usec = 0;

         if (select(sockfd + 1, NULL, &fdset, NULL, &tv) == 1)
         {
           int so_error;
           socklen_t len = sizeof so_error;
           getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
         }         
         //-------------------------------------
         
         /* send the request */
         total = strlen(message);
         sent = 0;
         do 
         {
          bytes = write(sockfd,message+sent,total-sent);
           if (bytes < 0)
           {      
               std::cout<<"ERROR writing message to socket\n";
           }
            if (bytes == 0)
            {
             break;
            }
             sent+=bytes;
         } while (sent < total);
         
         
         //dane walssciy
         //write(sockfd,dane,ilosc_danych);

         
        /* receive the response */
        memset(response_serv,0,sizeof(response_serv));
        total = sizeof(response_serv)-1;
        received = 0;
        do {
           bytes = read(sockfd,response_serv+received,total-received);
           if (bytes < 0)
           {              
               std::cout<<"ERROR reading response from socket\n";
           }
           if (bytes == 0)
              break;
           received+=bytes;
           } while (received < total);

        if (received == total)
        {            
            std::cout<<"ERROR storing complete response from socket\n";
        }

        
        close(sockfd);
        
        
        std::cout<<"Dane odebrane po reejestracji.... ("<<received<<")\n"<<response_serv;
        
        int indexStart = -1;
        
        for(int m=4; m<received; m++)
        {
            if(response_serv[m-4] == 13 && response_serv[m-3] == 10 && response_serv[m-2] == 13 && response_serv[m-1] ==10)
            {
                indexStart = m;
                break;
            }
        }
        
       
        char c1 = 0;
        char c2 = 0;
        
        memcpy(&c1, response_serv + indexStart ,1 ); 
        memcpy(&c2, response_serv + indexStart+1 ,1 ); 
        
        std::cout<<"\nKontrol "<<c1<<"|"<<c2<<"|";
        
        if(c1 !='%' | c2 != '#')
        {
            std::cout<<"\n!!! Nie mozna odczytaj zapisac rejestracji....";
            return false; //nie mozna odczytaj sygnatur
        }
         
    
        
      
        
        return true;
   
}

 

/**
 * Zarejestruj czytnik
 * @param Install
 * @param dane
 * @param ilosc_danych
 * @return 
 */
bool register_reader( unsigned long Install, char* ip, unsigned long tn)
{
          
      
          
          std::string POST = "";
          POST.append("POST ");
          POST.append("/reader");
          POST.append(" HTTP/1.0\r\n");
          
          POST.append("Host: ");
          POST.append("mm.edu.pl");
          POST.append("\r\n");
          
          POST.append("User-Agent: ");
          POST.append("mm web plugin/1.0 Błażej Kita ");
          POST.append("\r\n");
          
          POST.append("Content-Type: ");
          POST.append("application/x-www-form-urlencoded");
          POST.append("\r\n");
          
          //dane do wylania...
                       
             std::string dataContent = "";
       
          
             std::string strInstall = gxh_LongToString(Install);                                                    
             dataContent.append("register=");
             dataContent.append( strInstall );                          
                              
             dataContent.append("&ip=");
             dataContent.append( ip );   
             
             
             std::string seria = gxh_LongToString(tn); 
             dataContent.append("&seria=");
             dataContent.append( seria ); 
             
            
             
          POST.append("Content-Length: ");
          POST.append( gxh_IntToString( dataContent.length()  ) ); // + ramka=
          POST.append("\r\n");
          
          POST.append("\r\n");     
          POST.append(dataContent);
          
          
          std::cout<<"Wysylam dane do serwera: "<<POST.c_str()<<"\n\n";
          
          
          
          std::string URL = "mm.edu.pl" ;
          
          /* first what are we going to send and where are we going to send it? */
          int portno =        80;
          const char *host =        URL.c_str();
          const char *message_fmt = POST.c_str();  // "POST /apikey=%s&command=%s HTTP/1.0\r\n\r\n";

          struct hostent *serverx;
          struct sockaddr_in serv_addr;
          int sockfd, bytes, sent, received, total;
          char message[4096],response_serv[4096];
        

          /* fill in the parameters */      
          memcpy(message, message_fmt, strlen(message_fmt));

          /* create the socket */
         sockfd = socket(AF_INET, SOCK_STREAM, 0);
         if (sockfd < 0)
         {                        
             std::cout<<"error opening socket\n";
             return;
         }

          /* lookup the ip address */
         serverx = gethostbyname(host);
         if (serverx == NULL)
         {     
              close(sockfd);
              std::cout<<"not such host\n";
              return;
         }

         /* fill in the structure */
         memset(&serv_addr,0,sizeof(serv_addr));
         serv_addr.sin_family = AF_INET;
         serv_addr.sin_port = htons(portno);
         memcpy(&serv_addr.sin_addr.s_addr,serverx->h_addr,serverx->h_length);

         /* connect the socket */
         if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
         {
               std::cout<<"error connection\n";
               close(sockfd);
               return false;
         }
         
         
          //--setTimeOut-------------------------
         struct timeval tv;
         fd_set fdset;
         FD_ZERO(&fdset);
         FD_SET(sockfd, &fdset);
         tv.tv_sec = 3;             /* 3 second timeout */
         tv.tv_usec = 0;

         if (select(sockfd + 1, NULL, &fdset, NULL, &tv) == 1)
         {
           int so_error;
           socklen_t len = sizeof so_error;
           getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
         }         
         //-------------------------------------
         

         /* send the request */
         total = strlen(message);
         sent = 0;
         do 
         {
          bytes = write(sockfd,message+sent,total-sent);
           if (bytes < 0)
           {      
               std::cout<<"ERROR writing message to socket\n";
           }
            if (bytes == 0)
            {
             break;
            }
             sent+=bytes;
         } while (sent < total);
         
         
         //dane walssciy
         //write(sockfd,dane,ilosc_danych);

         
        /* receive the response */
        memset(response_serv,0,sizeof(response_serv));
        total = sizeof(response_serv)-1;
        received = 0;
        do {
           bytes = read(sockfd,response_serv+received,total-received);
           if (bytes < 0)
           {              
               std::cout<<"ERROR reading response from socket\n";
           }
           if (bytes == 0)
              break;
           received+=bytes;
           } while (received < total);

        if (received == total)
        {            
            std::cout<<"ERROR storing complete response from socket\n";
        }

        
        close(sockfd);
        
        
        std::cout<<"Dane odebrane po reejestracji czytnka.... ("<<received<<")\n"<<response_serv;
        
        int indexStart = -1;
        
        for(int m=4; m<received; m++)
        {
            if(response_serv[m-4] == 13 && response_serv[m-3] == 10 && response_serv[m-2] == 13 && response_serv[m-1] ==10)
            {
                indexStart = m;
                break;
            }
        }
        
       
        char c1 = 0;
        char c2 = 0;
        
        memcpy(&c1, response_serv + indexStart ,1 ); 
        memcpy(&c2, response_serv + indexStart+1 ,1 ); 
        
        std::cout<<"\nKontrol "<<c1<<"|"<<c2<<"|";
        
        if(c1 !='%' | c2 != '*')
        {
            std::cout<<"\n!!! Nie mozna odczytaj zapisac rejestracji....";
            return false; //nie mozna odczytaj sygnatur
        }
         
    
        
      
        
        return true;
   
}



//------------------------------------------------------------

class MMFrame
{
   private:    
       
       char* buffer;
       int   dataSize;
       
       short Ctrl;    //2 bajty     
       short Ctr2;    //2 bajty     
       unsigned long TN;       //4 bajty //typ urzedzeania..
       char* Mess;    //x bajtów..
       int MessSize;
       char CRC32[4];    //4 bajty
              
       short NrRamkiK;
       
       char* MessHead;
       char MeId[1]; //id wiadomosci
       char C[1];    //rozkaz..
       char AdrTyp[1]; //typ adresata // 0 - kontroler, 1 - przejscie
       char AdrNr[1]; //numer adresata, 0 - kontroler, 1-7 do przejść
       char I[2]; // index numer pierwszego rekord
       char Q[2]; //ilosc kolejnych rekordow..
       
       char Prot[2];
       unsigned long Install;
       char KeyISyg[4];
       unsigned long Time;
       
       
       char* Msg; //dane właściwe...
       int MsgSize;
       
       char CMAC[8];
       
       char L1[16]; //liczba losowa 1
       char L2[16]; //liczba losowa 2
       char L3[16]; //liczba losowa 3
       
       
       char KeySa[16]; //do podpisywania
       char KeySe[16]; //do szyfrowania..
       
       unsigned long TimeSyg;
       
       int socket;
       
       unsigned long* cardSyg;
       str_card* karty;
       int* ilosc_kart;
       
       int* ilosc_obiektow;
       unsigned long* sygnaturyObiektow;
     
       //Klucz producenta oprogramownai uzgodniony..
       /*
       unsigned char KeyPa[32] =  {
		0xCE,0x37,0xDF,0x5B,0x27,0x77,0xDB,0xD8,0x75,0x97,0xB0,0x0E,0x0C,0x5E,0x2F,0x6D,
                0x10,0xC1,0x19,0xA5,0x7E,0x43,0xFB,0xD7,0x43,0xD3,0x94,0x9B,0x90,0x07,0x0E,0xF8
	         };
      
        unsigned char KeyPe[32] =  {
		0x01,0x18,0x17,0x40,0x67,0x39,0xE3,0x02,0x75,0x6F,0xA8,0x0C,0xE2,0x2A,0x05,0x32,
                0x5C,0x60,0x5B,0x35,0xED,0x1B,0xEC,0x15,0x8E,0x1F,0xEC,0x18,0x12,0x74,0xE7,0xA6
	         };
        */
        
        //unsigned char KeyP[64];
        unsigned char KeyPp[64];
        unsigned char KeyPap[32] = {
                                     0xCE,0x37,0xDF,0x5B,0x27,0x77,0xDB,0xD8,0x75,0x97,0xB0,0x0E,0x0C,0x5E,0x2F,0x6D,
                                     0x10,0xC1,0x19,0xA5,0x7E,0x43,0xFB,0xD7,0x43,0xD3,0x94,0x9B,0x90,0x07,0x0E,0xF8 
                                      };
        unsigned char KeyPep[32] = {
                                     0x01,0x18,0x17,0x40,0x67,0x39,0xE3,0x02,0x75,0x6F,0xA8,0x0C,0xE2,0x2A,0x05,0x32,
                                     0x5C,0x60,0x5B,0x35,0xED,0x1B,0xEC,0x15,0x8E,0x1F,0xEC,0x18,0x12,0x74,0xE7,0xA6
                                  };
       
       
       char strCerKeyInstall[128];     //certyfikat klucza instalacji...
       char strCerConfProd[272];        // konfiguracja producenta
       char  strCerConfInstall[112]; // kongiruacja instalacji
       
       
       int* upgadeFileSize;
       char* upgradeBuffer;
       
   public:       
                     
       
       bool isCrypted; //szyfrowana... tak nie
       int typeFrame; 
       short NrR;     //2 bajty, numer ramki..
       
       
       void setIloscObj(int* ilosc_obj)
       {
           this->ilosc_obiektow = ilosc_obj;
       }
       
       
       void setSgnaturyObj(unsigned long* syg)
       {
           this->sygnaturyObiektow = syg;
       }
       
       void setIloscKart(int* ilosc_k)
       {
           this->ilosc_kart = ilosc_k;
       }
       
       void setTypUrzadzeniaTN(unsigned long tn)
       {
           this->TN = tn;
       }
       
       unsigned long getTypUrzadzeniaTn(){ return this->TN; }
       
       void setUpgradeFileSize(int* size)
       {
           this->upgadeFileSize = size;
       };
       
       void setUpgaredBuffer(char* buff)
       {
           this->upgradeBuffer = buff;
       };
       
       unsigned long getNumInstall()
       {
           return this->Install;
       }
       
       void setInstall(unsigned long install)
       {
           this->Install = install;
       }
       
       
       void setCards(str_card* ptrCard)
       {
           this->karty = ptrCard;
       }
       
       void setCardSyg(unsigned long* cardSyg)
       {
           this->cardSyg = cardSyg;
       }
       
       void setSocket(int s)
       {
           this->socket = s;
       }
       
       void setL1(char* l1)
       {
           memcpy(this->L1, l1,16);
       }
       
        void setL2(char* l2)
       {
           memcpy(this->L2, l2,16);
       }
        
       void setL3(char* l3)
       {
           memcpy(this->L3, l3,16);
       }
       
       void getL1(char* l1)
       {
           memcpy(l1, this->L1,16);
       }
       
       void getL2(char* l2)
       {
           memcpy(l2, this->L2,16);
       }
       
       void getL3(char* l3)
       {
           memcpy(l3, this->L3,16);
       }
       
       void getKeySa(char* keysa)
       {
           memcpy(keysa, this->KeySa,16);
       }
       
       void getKeySe(char* keyse)
       {
           memcpy(keyse, this->KeySe,16);
       }
       
       void getTimeSyg(unsigned long* time)
       {
           *time = this->TimeSyg;
       }
       
       void setKeySa(char* keySa)
       {
           memcpy(this->KeySa, keySa, 16);
       }
       
       void setKeySe(char* keySe)
       {
           memcpy(this->KeySe, keySe, 16);
       }
       
       void setTimeSyg( unsigned long TimeSyg)
       {
           this->TimeSyg = TimeSyg;
       }
       
       void setNumerRamki(short nr)
       {
           this->NrRamkiK = nr;           
       }
       
       void getNumerRamki(short* nr)
       {
           *nr = this->NrRamkiK;
       }
       
       
       MMFrame(char* data, int size)
       {
           this->buffer = new char[size];
           this->dataSize = size;
           
           memcpy(this->buffer, data, size);          
                      
           this->isCrypted = false; //czy ramka jest szyfrowania..
           this->typeFrame = -1;
           
           this->MessSize = 0;
           this->Mess = NULL;
           this->Msg = NULL;
           this->MsgSize = 0;
                    
           this->MessHead = NULL;
           
           this->Install = 0;
         
     
           //przelicz klucz producenta..                                      
            /*
            memset(this->KeyP,0,64);
            for(int mm=0; mm<32; mm++)
            {
                this->KeyP[mm] = this->KeyPa[mm];
            }
            
            for(int mm=0; mm<32; mm++)
            {
                this->KeyP[mm+32] = this->KeyPe[mm];
            }
           
           
            int sizeKeyS = 0;                        
         
            SHA256(this->KeyPa, 32, this->KeyPap, &sizeKeyS);
            SHA256(this->KeyPe, 32, this->KeyPep, &sizeKeyS);
            
            memset(this->KeyPp,0,64);
            for(int mm=0; mm<32; mm++)
            {
                this->KeyPp[mm] = this->KeyPap[mm];
            }
            
            for(int mm=0; mm<32; mm++)
            {
                this->KeyPp[mm+32] = this->KeyPep[mm];
            }
           */
            
            std::cout<<"\nKeyP'a: ";          
            for(int m=0; m<32; m++)
            {
               printf("%02x",   (int)((unsigned char)this->KeyPap[m]) );            
              std::cout<<" ";
            }    
            
          std::cout<<"\nKeyP'e: ";          
          for(int m=0; m<32; m++)
           {
               printf("%02x",   (int)((unsigned char)this->KeyPep[m]) );            
              std::cout<<" ";
           }  
           
           
           NrRamkiK = 1;
       };
       
       ~MMFrame()
       {                     
              delete[] this->buffer;
           
           if(this->Mess != NULL)
              delete[] this->Mess;
              
           if(this->Msg != NULL) 
              delete[] this->Msg;
           this->MessSize = 0;
           if(this->MessHead != NULL) 
              delete[] this->MessHead;
       };
     
       
       
       bool odczytajCertyfikaty()
       {
        
         //  if(this->Install <= 0 )  return false;
            
         
             
                  memset(strCerKeyInstall,0,128);     //certyfikat klucza instalacji...
                  memset(strCerConfProd,0,272);        // konfiguracja producenta
                  memset(strCerConfInstall,0,112); // kongiruacja instalacji
       
           
             
                  std::string confFile = "/var/www/mm_reader/cert/";
                  confFile.append( gxh_LongToString(this->TN ) );                   
                  confFile.append("_conf_prod_.cer.bin");
                  
                  std::string confKeyInstall = "/var/www/mm_reader/cert/";
                  confKeyInstall.append( gxh_LongToString(this->TN) );
                  confKeyInstall.append("_conf_key_install.cer.bin");
                  
                  std::string confInstall = "/var/www/mm_reader/cert/";
                  confInstall.append( gxh_LongToString(this->TN) );
                  confInstall.append("_conf_install.cer.bin");
                           
                  
             
                  
             
                  
                  
                   
                 std::ifstream  confFileHandle;
                 confFileHandle.open ( confFile.c_str(),  std::ios::in  | std::ios::binary); 
                 if (!confFileHandle.is_open()) 
                 { 
                     std::cout<<"\n\nNie mozna utworzyc pliku "<<confFile.c_str();   
                     return false;
                 }else
                 {
                   confFileHandle.read((char*)this->strCerConfProd,  272 );
                   confFileHandle.close();                                                      
                   
                 }
                 
                 
                  
                 std::ifstream  confKeyInstallHandle;
                 confKeyInstallHandle.open ( confKeyInstall.c_str(),    std::ios::in  | std::ios::binary);  
                 if (!confKeyInstallHandle.is_open()) 
                 { 
                     std::cout<<"\n\nNie mozna utworzyc pliku "<<confKeyInstall.c_str();                                    
                     return false;
                 }else
                 {
                    confKeyInstallHandle.read((char*)this->strCerKeyInstall,  128);
                    confKeyInstallHandle.close();
                 }
                                    
                 
                 std::ifstream  confInstallHandle;
                 confInstallHandle.open ( confInstall.c_str(),   std::ios::in  | std::ios::binary); 
                 if (!confInstallHandle.is_open()) 
                 { 
                     std::cout<<"\n\nNie mozna utworzyc pliku "<<confInstall.c_str();          
                     return false;
                 }else
                 {
                     confInstallHandle.read((char*)this->strCerConfInstall,  112 );
                     confInstallHandle.close();
                 }
          
                 return true;
       }       
              
       
       bool odczytajObiekt( char Grupa, char Index, unsigned long* syg, char* data, int *sizeOut, int sizeIn)
       {
           
             *syg = 0; //brak sygantury..
             *sizeOut = 0;
                   
           
                  std::string confInstall = "/var/www/mm_reader/configuration/";
                  confInstall.append( gxh_LongToString(this->TN) );
                  confInstall.append("_grp_");
                  confInstall.append( gxh_LongToString( (unsigned long)Grupa) ); //grupa obiektu
                  confInstall.append("_obj_");
                  confInstall.append( gxh_LongToString( (unsigned long)Index) ); //grupa obiektu
                  confInstall.append(".conf");
                  
                  
                  std::ifstream  confFileHandle;
                  confFileHandle.open ( confInstall.c_str(),  std::ios::in  | std::ios::binary); 
                  if (!confFileHandle.is_open()) 
                  { 
                    // std::cout<<"\n\nNie mozna utworzyc pliku "<<confInstall.c_str();                                             
                     return false;
                  }else
                  {
                                        
                   confFileHandle.seekg(0,std::ios_base::end); //przesun na koniec..
                   int size = confFileHandle.tellg();                   
                   confFileHandle.seekg(0,std::ios_base::beg); //przesun na koniec.. 
                      
                      
                   if(sizeIn < size) 
                   {
                       std::cout<<"\nZbyt maly bufor dla pliku "<<confInstall.c_str();
                       return false;
                   }
                   
                   char buff[1024 * 50]; //50k powinno starczyc
                   
                   confFileHandle.read((char*)buff,  size );
                   confFileHandle.close();            
                    
                   std::cout<<"\nOdczytano plik "<<confInstall.c_str()<<" rozmiar "<<size;
                   
                   if(size>17)
                   {
                      *sizeOut = size-16;; //bez sygnatury..
                      
                      memcpy(syg,buff+12,4); //skopiuj syganture..
                      memcpy(data, buff+16,size-16);
                      
                      return true;
                   }
                  }
                   
                  return false;
       }
       
       
       bool analizeFrame(int* type, char* frameReady, int* sizeFrame)
       {
        
           
         //  std::cout<<"\nFrame: ";          
          // for(int m=0; m<this->dataSize; m++)
         //  {
         //      printf("%02x",   (int)((unsigned char)this->buffer[m]) );            
          //     std::cout<<" ";
         //  }                                 
           
           if(this->dataSize < 12) return false; //zbyt mało danych by utworzyc ramke..           
           
           
           memcpy(&this->Ctrl, this->buffer + 0 , 2); //skopiuj dwa bajty..
           memcpy(&this->NrR,  this->buffer + 2 , 2); //skopiuj dwa bajty..
           memcpy(&this->TN,  this->buffer + 4 , 4); //skopiuj dwa bajty..        
          
           this->MessSize = this->dataSize - 8 - 4; //-8 pierwszych wartosci - crc32
           
           if(this->MessSize<=0)
           {
               std::cout<<"\nBrak wiadomosci\n";
               return false;
           }
           
           memcpy(this->CRC32,this->buffer+8 + this->MessSize  ,4);
            
           
           if(this->Mess != NULL) delete[] this->Mess;
           this->Mess = new char[this->MessSize]; //wiadomość właściwa..
           memcpy(this->Mess, this->buffer+8, this->MessSize);
           
         
         //  std::cout<<"\nMess: ";          
         //  for(int m=0; m<this->MessSize; m++)
          // {
          //     printf("%02x",   (int)((unsigned char)this->Mess[m]) );            
          //     std::cout<<" ";
         //  }  
           
         //  std::cout<<"\nCRC32: ";          
         //  for(int m=0; m<4; m++)
         //  {
          //     printf("%02x",   (int)((unsigned char)this->CRC32[m]) );            
          //     std::cout<<" ";
          // } 
           
         //  std::cout<<"\nCtrl: "<<std::bitset<16>(this->Ctrl);
           
           if( (this->Ctrl & 0b0100000000000000) == 0b0100000000000000) 
           {
               this->isCrypted = true;                        
           }else
           {
               this->isCrypted = false;
           }
           
           if(( (this->Ctrl & 0b0010000000000000) != 0b0010000000000000) && ( (this->Ctrl & 0b0001000000000000) != 0b0001000000000000) ) //bit 13 i 12 == 0 i 0 
           {
               this->typeFrame = 1; //negocjowanie klucza sesji..
           }
           
           if(((this->Ctrl & 0b0010000000000000) != 0b0010000000000000) && ((this->Ctrl & 0b0001000000000000) == 0b0001000000000000) ) //bit 13 i 12 == 0 i 1
           {
               this->typeFrame = 2; //przesylanie ceryfikatow i upgradów
           }
           
           if(((this->Ctrl & 0b0010000000000000) == 0b0010000000000000) && ((this->Ctrl & 0b0001000000000000) != 0b0001000000000000) ) //bit 13 i 12 == 1 i 0
           {
               this->typeFrame = 3; //transmisja w sesji inicjowana przez urzadzenie...
           }
           
           if(((this->Ctrl & 0b0010000000000000) == 0b0010000000000000) && ((this->Ctrl & 0b0001000000000000) == 0b0001000000000000) ) //bit 13 i 12 == 1 i 1
           {
               this->typeFrame = 4; //transmisja w sesji inicjowana przez komputer...
           }
           
           
                                      
          
          
           
          if(!this->isCrypted) //tylko w wiadomosci syzfrowanej wystepuje podpis CMAC
           {           

             //Nagłowek wiadomości................................................
              if(this->MessHead == NULL) delete[] this->MessHead;
              this->MessHead = new char[8]; //nagłowek niezaszyfrowany..
              
             memcpy(this->MessHead, this->Mess, 8); //skopiuj nagłowek wiadomości.. jest na poczatku wiadomosci..
                     
              
          //   std::cout<<"\nDataNotCrypted... checking session ";   
                         
           // std::cout<<"\nHK: ";          
           //  for(int m=0; m<8; m++)
           //  {
           //    printf("%02x",   (int)((unsigned char)this->MessHead[m]) );            
           //    std::cout<<" ";
           //  } 
           
             memcpy(this->MeId, this->MessHead + 0 ,1 );
             memcpy(this->C, this->MessHead + 1 ,1 );        
             memcpy(this->Prot, this->MessHead + 2 ,2 );  //INDEX                                             
             memcpy(&this->Time, this->MessHead + 4 ,4 );         //
           
            // printf("\nMeId %02x",   (int)((unsigned char)this->MeId[0]) );            
            // printf("\nC %02x",   (int)((unsigned char)this->C[0]) );            
           //  printf("\nProt %02x",   (int)((unsigned char)this->Prot[0]) );     printf(" %02x",   (int)((unsigned char)this->Prot[1]) );                                  
           //  printf("\nTime %02x",   (int)((unsigned long)this->Time) ); std::cout<<" T2: "<<this->Time;          
    
             if(this->C[0] == 'X') // Rozkaz pobrania certyfikatu...
             {
                std::cout<<"\n\n\nOtrzymano rozkaz 'X' pobranie certyfikatu";
                       
                short indeX =0; 
                memcpy(&indeX, this->MessHead + 2 ,2 );  //INDEX                              
                                                                    
                
                
                  std::string confProd = "/var/www/mm_reader/cert/";
                  confProd.append( gxh_LongToString(this->TN) );
                  confProd.append("_conf_prod_.cer.bin");
                  
                  
                  std::string confKeyInstall = "/var/www/mm_reader/cert/";
                  confKeyInstall.append( gxh_LongToString(this->TN) );
                  confKeyInstall.append("_conf_key_install.cer.bin");
                  
                  std::string confInstall = "/var/www/mm_reader/cert/";
                  confInstall.append( gxh_LongToString(this->TN) );
                  confInstall.append("_conf_install.cer.bin");
                
                  
                 std::ifstream  confFileHandle;
                 confFileHandle.open ( confProd.c_str(),  std::ios::in  | std::ios::binary); 
                 
                 bool isExist = false;
                 if (confFileHandle.is_open()) 
                 { 
                     isExist = true;
                     confFileHandle.close();
                 }
                  
     
                if(this->Install == 0 && isExist == false)
                {
                  this->Install = time(NULL);   
                    
               
                 
                   
                   
                  
                  /*
                  * Urządznie chce pobrać certyfikaty więc jest to pierwsze uruchomienie...
                   * 1) utworzenie konfiguracji producenta oprogramowania + zapis jej do pliku
                   * 2) certyfikat klucza instalacji + zapis do pliku
                   * 3) konfiguracjia instaliacji + zapis do pliku
                  */                                
                   
                   
                  //certyfikat klucza instalacji..
                   int c1Size  = 128;
                   char cerKeyInstall[  c1Size ]; //heade + certyfikat + podpis
                   memset(cerKeyInstall,0,c1Size );
                   
                   char c1Typ = 0;
                   c1Typ |= 0b0000101; //certifikat klucza instalacji...- szufrowanie kluczem producenta oprogramownaia..
                   char c1Len = c1Size / 16; //ilosc blokow 16 bitowych...
                   short c1Flag = 0;
                   unsigned long c1Time =  time(NULL); //czas wystawineia certyfikatu..
                   unsigned long c1Device = 297926675; //KDM - C150 urządznie..
                   unsigned long c1Licznik =0; //licnzik blokow przy szyfrowaniau.. wpisac 0 tutu
                   
                   //tututu
                   c1Device = this->TN;
                   
                   
                   //header..
                   memcpy(cerKeyInstall+0, &c1Typ,1);
                   memcpy(cerKeyInstall+1, &c1Len,1);
                   memcpy(cerKeyInstall+2, &c1Flag,2);
                   memcpy(cerKeyInstall+4, &c1Time,4);
                   memcpy(cerKeyInstall+8, &c1Device,4);
                   memcpy(cerKeyInstall+12, &c1Licznik,4);
                   
                   
                   unsigned long c1DTime = time(NULL);                                      
                   memcpy(cerKeyInstall+16, &c1DTime,4);
                   
                   /*
                   for(int ww=0; ww<32; ww++)
                   {
                       char KeyIa = rand() % 240;   // 0 -239 //do podpoisu 
                       char KeyIe = rand() % 140 + 100;   // 0 -239 //do syfrowania..
                       
                       memcpy( cerKeyInstall+20 + 0 +  ww, &KeyIa,1 );
                       memcpy( cerKeyInstall+20 + 32 + ww, &KeyIe,1 );
                   }                   
                   
                    * 
                    */
                   
                   //wpis chwilowo na stałe klucze..
                   // te klucz sa wykorzystywane nizej... NIE USUWAC
                   
                   char KeyIaTmp[32] = {
                       0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
                   };
                   
                   char KeyIeTmp[32] = {
                       0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F   
                   };
                   
                   for(int ww=0; ww<32; ww++)
                   {
                       char KeyIa = rand() % 240;   // 0 -239 //do podpoisu 
                       char KeyIe = rand() % 140 + 100;   // 0 -239 //do syfrowania..
                   
                       KeyIaTmp[ww] = KeyIa;
                       KeyIeTmp[ww] = KeyIe;
                   }    
                   
                   
                   for(int ww=0; ww<32; ww++)
                   {                      
                       memcpy( cerKeyInstall+20 + 0 +  ww, &KeyIaTmp[ww],1 );
                       memcpy( cerKeyInstall+20 + 32 + ww, &KeyIeTmp[ww],1 );
                   }   
                   //--koniec kluczy..
                   
                   
                   memset(cerKeyInstall +84,0,20); //zerujemy nazwe wystawcy..                   
                   const char* wystawca = "Blazej Kita";                   
                   memcpy(cerKeyInstall +84, wystawca, strlen(wystawca));
                   
                   memcpy(cerKeyInstall +104, &this->Install,4);
                   memset(cerKeyInstall +108,0,4);  //Reserved
       
                                                             
                   
                   char bufferCMac[1024];
                   memset(bufferCMac,0,1024);
                   int sizeCMac = 0;
                   createCMAC((const char*)cerKeyInstall, this->KeyPap, 112, 32,bufferCMac,&sizeCMac); // klucz 16 bitowy?
                   
                   memcpy(cerKeyInstall+112, bufferCMac,16);
                   
                   
     
                   
                   //zaszyfruj dane + podpis..
                   //-------------------------------
                    std::cout<<"\n\nCert Klucza instalacji przed zaszyfrowaniem: \n";          
                    for(int m=0; m<128; m++) 
                    {                              
                        printf("%02x",   (int)((unsigned char)( cerKeyInstall[m])) );    std::cout<<" ";
                    } 
                   
                    char* encrypteddMess = new char[112]; //szyfrujemy wszystko bez nagłowka...
               
                    //szyfrujemy dane od pola data do konca pola sign                            
                    aes256Encrypt((char*)(cerKeyInstall+16), this->KeyPep,112, 32, encrypteddMess,(char*)cerKeyInstall,16);        //vektor inicjujacy stanowi nagowek..
                                           
                    memcpy((char*)(cerKeyInstall+16), encrypteddMess, 112);                                
                 
                    delete[] encrypteddMess;
                                        
                    
                    std::cout<<"\n\nCert Klucza instalacji po zaszyfrowaniu: \n";                                 
                    for(int m=0; m<128; m++) 
                    {                        
                        printf("%02x",   (int)((unsigned char)( cerKeyInstall[m])) );    std::cout<<" ";
                    } 
                   //-------------------------------
                    
              
                   
                   
                   
                    //zapisz konfiguracje..
                  std::cout<<"\nZapisuje danych "<<128 <<" Dane: "<<(char*)cerKeyInstall;
                  std::ofstream confKeyInstallHandle;
                  confKeyInstallHandle.open ( confKeyInstall.c_str(),   std::ofstream::binary ); 
                  confKeyInstallHandle.write((char*)cerKeyInstall, 128 );
                  confKeyInstallHandle.close();
            
                   
                  
                  //konifuguracja producenta oprogramownaia.... 0b0001001
                   int c2Size  = 272;
                   char cerConfProd[  c2Size ]; //heade + certyfikat + podpis
                   memset(cerConfProd,0,c2Size );
                   
                   char c2Typ = 0;
                   c2Typ |= 0b0001001; //certifikat klucza instalacji...- szufrowanie kluczem producenta oprogramownaia..
                   char c2Len = c2Size / 16; //ilosc blokow 16 bitowych...
                   short c2Flag = 0;
                   unsigned long c2Time =  time(NULL); //czas wystawineia certyfikatu..
                   unsigned long c2Device = 297926675; //KDM - C150 urządznie..
                   unsigned long c2Licznik =0; //licnzik blokow przy szyfrowaniau.. wpisac 0 tutu
                   
                    //tututu
                   c2Device = this->TN;
                   
                   //header..
                   memcpy(cerConfProd+0, &c2Typ,1);
                   memcpy(cerConfProd+1, &c2Len,1);
                   memcpy(cerConfProd+2, &c2Flag,2);
                   memcpy(cerConfProd+4, &c2Time,4);
                   memcpy(cerConfProd+8, &c2Device,4);
                   memcpy(cerConfProd+12, &c2Licznik,4);
                    
                  
                  // memset(cerConfProd+16,0,1) ; //wersja konfiguracji
                   
                    char iloscTypL = 0;
                    char iloscTypP = 1;
                    memcpy(cerConfProd+16,&iloscTypL,1) ; //ilosc typow rejestracji.
                    memcpy(cerConfProd+17,&iloscTypP,1) ; //ilosc typow rejestracji.
                   
                     memset(cerConfProd+18,0x80,1) ; //RegTyp
                     memset(cerConfProd+19,0x00,1) ; //ReqRes
                     memset(cerConfProd+20,0x30,1) ; //ReqHUE
                     memset(cerConfProd+21,0x00,1) ; //RegTxt przyciemnienie...
                   
                     memset(cerConfProd+22,0,12) ; //RegName nazwa restracaji
                     const char* nazwaRej = "NORMAL";
                     memcpy(cerConfProd+22, nazwaRej, strlen(nazwaRej));
                     
                     //nazwa po angielsku..
                     memset(cerConfProd+34,0,12) ; //RegName nazwa restracaji
                     const char* nazwaRejAng = "NORMAL";
                     memcpy(cerConfProd+34, nazwaRejAng, strlen(nazwaRejAng));
                     
                     //tutau inne typy rejestracji..
                     
                     // 7 * 16 = 112 więcej...
                     memset(cerConfProd+46,0,196);
                     //...........................
                   
                   memset(cerConfProd+242,0,14) ; //zarjezerwowane.. 256
            
              
                   
                                            
                   memset(bufferCMac,0,1024);                
                   createCMAC((const char*)cerConfProd, this->KeyPap, 256, 32,bufferCMac,&sizeCMac);
                   
                   memcpy( (char*)(cerConfProd + 256), bufferCMac,16);
                    
                   
                    //zaszyfruj dane + podpis..
                   //-------------------------------
                    std::cout<<"\n\nCert Konf producenta  przed zaszyfrowaniem: \n";          
                    for(int m=0; m<272; m++) 
                    { 
                        printf("%02x",   (int)((unsigned char)cerConfProd[m] ) );    std::cout<<" "; 
                    } 
                   
                    char* encrypteddMess1 = new char[272]; //szyfrujemy wszystko bez nagłowka...
                    //szyfrujemy dane od pola data do konca pola sign                   
                    aes256Encrypt((char*)(cerConfProd+16), this->KeyPep, 256, 32, encrypteddMess1,(char*)cerConfProd,16);         //naglwek jest wektorem inicjujacym..
                    
                    memcpy((char*)(cerConfProd+16), encrypteddMess1,  256);                                
                    
                    delete[] encrypteddMess1;
                   
                    std::cout<<"\n\nCert Konf producenta po zaszyfrowaniu: \n";          
                    for(int m=0; m<272; m++) 
                    {                 
                        printf("%02x",   (int)((unsigned char)cerConfProd[m] ) );    std::cout<<" "; 
                    } 
                   //-------------------------------
                   
                    //zapisz konfiguracje...    
                    
                   //  std::cout<<"\nZapisuje danych "<< sizeof(cert_confg_prod_ready)<<" dane "<<(char*)&strConfProd;
                     
                 
                        
                     std::ofstream confPordHandle;
                     confPordHandle.open ( confProd.c_str(),   std::ofstream::binary ); 
                     confPordHandle.write( (char*) cerConfProd,272 );
                     confPordHandle.close();  
                   
              
                     
                     //konfiguracja instalacji.... 0b0001101
                    int c3Size  = 112;
                   char cerConfInstall[  c3Size ]; //heade + certyfikat + podpis
                   memset(cerConfInstall,0,c3Size );
                   
                   char c3Typ = 0;
                   c3Typ |= 0b0001100; //certifikat kluczinstalacji szyfrowanie kluczem instalacji.. KeyI
                   char c3Len = c3Size / 16; //ilosc blokow 16 bitowych...
                   short c3Flag = 0;
                   unsigned long c3Time =  time(NULL); //czas wystawineia certyfikatu..
                   unsigned long c3Device = 297926675; //KDM - C150 urządznie..
                   unsigned long c3Licznik =0; //licnzik blokow przy szyfrowaniau.. wpisac 0 tutu
                   
                   
                    //tututu
                   c3Device = this->TN;
                   
                   //header..
                   memcpy(cerConfInstall+0, &c3Typ,1);
                   memcpy(cerConfInstall+1, &c3Len,1);
                   memcpy(cerConfInstall+2, &c3Flag,2);
                   memcpy(cerConfInstall+4, &c3Time,4);
                   memcpy(cerConfInstall+8, &c3Device,4);
                   memcpy(cerConfInstall+12, &c3Licznik,4);
                   
                   memset(cerConfInstall+16, 0,1);  //CfgV
                   memset(cerConfInstall+17, 0,1);  //CfgRes
                   
                   char SerSt = 0;
                    SerSt |= 0b00000011; //wazna nazwa domeny i ip serwera podtawowego...
                   memcpy(cerConfInstall+18, &SerSt ,1);  //SerSt
                   
                   memset(cerConfInstall+19, 0,63);  //nazwa domeny serwera podstawosego
                   const char* serName = "pg8.sh0t.org";
                   memcpy(cerConfInstall+19, serName, strlen(serName));
                   
                   memset(cerConfInstall+82, 188,1);  // IP 
                   memset(cerConfInstall+83, 116,1);  // IP 
                   memset(cerConfInstall+84, 37,1);  // IP 
                   memset(cerConfInstall+85, 38,1);  // IP 
                   
                   short serPort = 49160; //
                   serPort = 2240; //zamieniamy na latiendia..
                   memcpy(cerConfInstall+86, &serPort,2);  // PORT                 
                                              
                   
                   memset(cerConfInstall+88, 188,1);  // IP2 
                   memset(cerConfInstall+89, 116,1);  // IP2 
                   memset(cerConfInstall+90, 37,1);  // IP2 
                   memset(cerConfInstall+91, 38,1);  // IP2 
                                  
                   memcpy(cerConfInstall+92, &serPort,2);  // PORT
                                     
                   memset(cerConfInstall+94,0,2); // reserved..
                    
                     
                   
                    memset(bufferCMac,0,1024);                
                    createCMAC((const char*)cerConfInstall, KeyIaTmp , 96, 32,bufferCMac,&sizeCMac);
                   
                    memcpy(cerConfInstall+96, bufferCMac,16);
                    
             
                            //zaszyfruj dane + podpis..
                   //-------------------------------
                    std::cout<<"\n\nCert Konf instalacji  przed zaszyfrowaniem: \n";          
                    for(int m=0; m<112; m++)  
                    {                    
                        printf("%02x",   (int)((unsigned char)cerConfInstall[m] ) );    std::cout<<" "; 
                    } 
                   
                    
                   
                    
                    char* encrypteddMess2 = new char[96]; //szyfrujemy wszystko bez nagłowka...
                    //szyfrujemy dane od pola data do konca pola sign                   
                    aes256Encrypt((char*)(cerConfInstall+16), KeyIeTmp  , 96, 32, encrypteddMess2,(char*)cerConfInstall,16);        //nagowek jest wektorem inicjujacym
                    
                    memcpy((char*)(cerConfInstall+16), encrypteddMess2,  96);                                
                    
                    delete[] encrypteddMess2;
                   
                    std::cout<<"\n\nCert Konf instalacji po zaszyfrowaniu: \n";          
                    for(int m=0; m<112; m++)  
                    {                         
                        printf("%02x",   (int)((unsigned char)cerConfInstall[m] ) );    std::cout<<" "; 
                    }
                   //-------------------------------
                    
                         
                    std::ofstream confInstallHandle;
                    confInstallHandle.open ( confInstall.c_str(),  std::ofstream::binary); 
                    confInstallHandle.write((char*)cerConfInstall, 112 );
                    confInstallHandle.close();
                    
                 
                }
                
                
              
                bool retCer = this->odczytajCertyfikaty();
                
                if(!retCer)
                {
                    std::cout<<"\n\nNie mozna odczytaj certyfikatow!!! "<<this->Install<<"\n";
                    return false;
                }
              
                //teraz ramki... ehehehehehe
                
                unsigned long index =0;
                
                memcpy(this->MeId, this->MessHead + 0 ,1 );
                memcpy(this->C, this->MessHead + 1 ,1 );        
                memcpy(this->Prot, this->MessHead + 2 ,2 );                       
                memcpy(&index, this->MessHead + 2 ,2 );                       
                memcpy(&this->Time, this->MessHead + 4 ,4 );    
                
                std::cout<<"\nIndex: "<<index<<" ";
                
                if(index == 1) //konfiguracja producenta oprogramownai..
                {
                     
                   short sizeResponse =292 ; //naglowe  + naglowek + dane + crc
                   char response[sizeResponse];
                 
                
                      short CtrlResponse = sizeResponse;    //2 bajty     
                      CtrlResponse |= 0b0000000000000000; //14 nie zyfrowwniae ramki....
                      CtrlResponse |= 0b0001000000000000; //przesylanie certyfikatow poza siesja..
                      CtrlResponse |= 0b0000100000000000; //bit 11 nadaje komputer
                                     
                      
                      short NrRResponse = this->NrR; //kolejny numer ramki..
                      long  TNResponse =  this->TN;                
                      this->NrRamkiK = NrRResponse;
                                                                       
                      
                     memcpy(response+0,&CtrlResponse,2);
                     memcpy(response+2,&NrRResponse,2);
                     memcpy(response+4,&TNResponse,4);
                     
                     memcpy(response+8, this->MessHead,8);
                     
                     memcpy(response+16, this->strCerConfProd , 272 );
               
                              
                     unsigned int crc = crc32b(response, sizeResponse-4);                       
                     memcpy(response + sizeResponse - 4 ,&crc,4); 
                            
                     std::cout<<"\n\nResponse (konfiguracja producenta oprogramowania)\n";          
                     for(int m=0; m<sizeResponse; m++)
                       {
                         printf("%02x",   (int)((unsigned char)response[m]) );            
                         std::cout<<" ";
                       }                     
               
                      *type = 4; //wyslano w klasie...                                
                      write(this->socket , response ,sizeResponse  );                                             
                      return true;                
                      std::cout<<"\n\n\n";                      
                }
                
                if(index == 2) //certyfikat klucza instalacji..
                {
                   short sizeResponse = 8 +  8 + 128  + 4 ; //naglowe  + naglowek + dane + crc
                   char response[sizeResponse];
                 
                
                      short CtrlResponse = sizeResponse;    //2 bajty     
                      CtrlResponse |= 0b0000000000000000; //14 nie szyfrowwniae ramki...
                      CtrlResponse |= 0b0001000000000000; //przesylanie certyfikatow poza siesja..
                      CtrlResponse |= 0b0000100000000000; //bit 11 nadaje komputer
                                     
                      
                      short NrRResponse = this->NrR; //kolejny numer ramki..
                      long  TNResponse =  this->TN;                
                      this->NrRamkiK = NrRResponse;
                                                                       
                      
                     memcpy(response+0,&CtrlResponse,2);
                     memcpy(response+2,&NrRResponse,2);
                     memcpy(response+4,&TNResponse,4);
                     
                     memcpy(response+8, this->MessHead,8);
                     
                     memcpy(response+16, this->strCerKeyInstall ,128 );
               
                              
                     unsigned int crc = crc32b(response, sizeResponse-4);                       
                     memcpy(response + sizeResponse - 4 ,&crc,4); 
                            
                     std::cout<<"\n\nResponse (certyfikat klucza instalacji)\n";                  
                     for(int m=0; m<sizeResponse; m++)
                       {
                         printf("%02x",   (int)((unsigned char)response[m]) );            
                         std::cout<<" ";
                       }                     
               
                      *type = 4; //wyslano w klasie...                                
                      write(this->socket , response ,sizeResponse  );                                             
                      return true;                
                      std::cout<<"\n\n\n";
                      
                }
                
                if(index == 3) //konfiguracja instalacji..
                {
                   short sizeResponse = 8 +  8 +112 + 4 ; //naglowe  + naglowek + dane + crc
                   char response[sizeResponse];
                 
                
                      short CtrlResponse = sizeResponse;    //2 bajty     
                      CtrlResponse |= 0b0000000000000000; //14 nie szyfrowwniae ramki...
                     CtrlResponse |= 0b0001000000000000; //przesylanie certyfikatow poza siesja..
                      CtrlResponse |= 0b0000100000000000; //bit 11 nadaje komputer
                                     
                      
                      short NrRResponse = this->NrR; //kolejny numer ramki..
                      long  TNResponse =  this->TN;                
                      this->NrRamkiK = NrRResponse;
                                                                       
                      
                     memcpy(response+0,&CtrlResponse,2);
                     memcpy(response+2,&NrRResponse,2);
                     memcpy(response+4,&TNResponse,4);
                     
                     memcpy(response+8, this->MessHead,8);
                     
                     memcpy(response+16, this->strCerConfInstall , 112 );
               
                              
                     unsigned int crc = crc32b(response, sizeResponse-4);                       
                     memcpy(response + sizeResponse - 4 ,&crc,4); 
                            
                      std::cout<<"\n\nResponse (konfiguracja instalacji)\n";                
                     for(int m=0; m<sizeResponse; m++)
                       {
                         printf("%02x",   (int)((unsigned char)response[m]) );            
                         std::cout<<" ";
                       }                     
               
                      *type = 4; //wyslano w klasie...                                
                      write(this->socket , response ,sizeResponse  );                                             
                      return true;                
                      std::cout<<"\n\n\n";
                  
                }
             
             }
             
             
             if(this->C[0] == '1') //rozkaz 1 
             {              
                 
                memcpy(this->L1, this->Mess + 8, 16); //po nagłowku HK8
                memcpy(&this->Install, this->Mess + 24, 4); //numer instalacji...
                memcpy(this->KeyISyg, this->Mess + 28, 4); //sygnatura klucza instalacji
             
                bool retCer = this->odczytajCertyfikaty(); //odczytaj klicze z certyfikatów wedlug numer intalacji..
                
                if(!retCer)
                {
                    std::cout<<"\n\nNie mozna odczytaj certyfikatow!!! "<<this->Install<<"\n";
                    
                   const char* dText = "Numer instalacji nie zostal rozpoznany";
                   *type = 4; //wyslano w klasie...                                
                   write(this->socket , dText ,strlen(dText)  );                                             
                   return true;                
                   std::cout<<"\n\n\n";              
                }
                
               // std::cout<<"\nL1: ";          
              //  for(int m=0; m<16; m++)
               // {
               //   printf("%02x",   (int)((unsigned char)this->L1[m] ) );            
               //   std::cout<<" ";
               // }   
                
                // std::cout<<"\nInstall: ";          
                
                //  printf("%02x",   (int)((unsigned char)this->Install ) );            
                
                 
               // std::cout<<"\nKeyISyg: ";          
               // for(int m=0; m<4; m++)
               // {
               //   printf("%02x",   (int)((unsigned char)this->KeyISyg[m] ) );            
               //   std::cout<<" ";
              //  }
                
                
                std::cout<<"\n\nOtrzymano rozkaz nr 1, budowanie odpowiedzi:\n\n";
                
                char MessHead2[8];
                char rozkaz2 = '2';
                memcpy(MessHead2, this->MessHead,8);                
                memcpy(MessHead2+1,&rozkaz2,1 );
                
              //  std::cout<<"\nHK2: ";          
              //  for(int m=0; m<8; m++)
              //  {
              //    printf("%02x",   (int)((unsigned char)MessHead2[m]) );            
              //    std::cout<<" ";
              //  } 
                
                
                for(int m=0; m<16;m++)
                {
                    //this->L2[m] = rand() % 100;
                    this->L2[m] = 1;
                }
                
             //   std::cout<<"\nL2: ";          
             //   for(int m=0; m<16; m++)
              //  {
              //    printf("%02x",   (int)((unsigned char)this->L2[m] ) );            
              //    std::cout<<" ";
             //   }  
                
                char ciag[90];
                memset(ciag,0,90);
                
                memcpy(ciag+0, &this->TN, 4);
                memcpy(ciag+4, this->MessHead, 8);
                memcpy(ciag+12,this->L1, 16);
                memcpy(ciag+28, &this->Install, 4);
                memcpy(ciag+32, this->KeyISyg, 4);
                memcpy(ciag+36, MessHead2, 8);
                memcpy(ciag+44, this->L2, 16);
                
              //   std::cout<<"\nCiag do Mac: ";          
               // for(int m=0; m<60; m++)
               // {
              //    printf("%02x",   (int)((unsigned char)ciag[m] ) );            
              //    std::cout<<" ";
              //  } 
                
                //klucz do podpisu...
                char klucz[32] =  {
		0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,				//KeyA - klucz do podpisu
		0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
		0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
		0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
	         };

                
                //odczytujemy klucz z certyfikatu który jest zaszyfrowany....
                char* encrypteddMess = new char[112]; //szyfrujemy wszystko bez nagłowka...                                           
                aes256Decrypt((char*)(this->strCerKeyInstall+16), this->KeyPep,112, 32, encrypteddMess,(char*)this->strCerKeyInstall,16);        //vektor inicjujacy stanowi nagowek..                                                                                                   
                memcpy(klucz, encrypteddMess+20 - 16, 32 );
                delete[] encrypteddMess;
                               
                
                
                
                 
                char bufferCMac[1024];
                memset(bufferCMac,0,1024);
                int sizeCMac = 0;
                createCMAC(ciag,klucz,60,32, bufferCMac, &sizeCMac);
                
                 std::cout<<"\nKey 111111111............................................: ";          
                for(int m=0; m<32; m++)
                {
                  printf("%02x",   (int)((unsigned char)klucz[m] ) );            
                  std::cout<<" ";
                }  
                
              //  std::cout<<"\nCMAC: ";
              //   for(int m=0; m<sizeCMac; m++)
              //  {
               //   printf("%02x",   (int)((unsigned char)bufferCMac[m] ) );            
               //   std::cout<<" ";
              //  } 
                
                
                
     
               
               char response[500];
               memset(response,0,500);
               
               memcpy(response,this->buffer,8); //nagówek ramki.. CTR + 2 NRR 2  + TN 4 
               
              
               this->Ctr2 =  0b0000100000101100; //nadaje komputer, serwer //nadaje komputer 1  i rozmiar ramki..
               memcpy(response,&this->Ctr2,2);
               
               memcpy(response+8,MessHead2,8); //8 bajtowy nagówek..
               memcpy(response+16,this->L2,16);
               //memcpy(response+32,bufferCMac,16);
               memcpy(response+32,bufferCMac,8); //tylko pierwsze osiem
             
               
                 //https://crccalc.com/
                //unsigned int table[256];
                //crc32::generate_table(table);
                //unsigned int crc = crc32::update(table, 0, response, 56);             
                
                unsigned int crc = crc32b(response, 40);

               
               memcpy(response+40, &crc,4);
               
            
              //  std::cout<<"\nReady to send: ";
               //  for(int m=0; m<44; m++) 
               // {
               //   printf("%02x",   (int)((unsigned char)response[m] ) );            
               //   std::cout<<" ";
              //  } 
                
                std::cout<<"\n\n------------------\n";
               // 
                
                
                *type = 1; //odebranie rozkazu 1 w negocjacji sesji...
                *sizeFrame = 44;                
                memcpy(frameReady, response, 44);
                return true;
                
      
                
               
             } //koniec rozkazu 1.....             
          
             
             if(this->C[0] == '3') //rozkaz 2
             {              
                 
                bool retCer = this->odczytajCertyfikaty(); //odczytaj klicze z certyfikatów wedlug numer intalacji.. 
                
                if(!retCer)
                {
                    std::cout<<"\n\nNie mozna odczytaj certyfikatow!!! "<<this->Install<<"\n";
                    return false;
                }
                
                 
                char CMAC3[8];
                 
                memcpy(this->L3, this->Mess + 8, 16); //po nagłowku HK8
                memcpy(CMAC3, this->Mess + 24, 8); //numer instalacji...    
             
               // std::cout<<"\nL3: ";          
               // for(int m=0; m<16; m++)
              //  {
              //    printf("%02x",   (int)((unsigned char)this->L3[m] ) );            
              //    std::cout<<" ";
              //  }   
               
                // std::cout<<"\nCMAC3: ";          
              //  for(int m=0; m<8; m++)
              //  {
               //   printf("%02x",   (int)((unsigned char)CMAC3[m] ) );            
               //   std::cout<<" ";
               // }  
                
                //wylicz podpis cmac by zweryfikowac dane..
                 
                 
                 
                std::cout<<"\n\nOtrzymano rozkaz nr 3, budowanie odpowiedzi:\n\n";
                
                
                
                   //klucz do szyfrowania
                char klucz[32] =  {
		0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,				//KeyE - klucz do kodowania
		0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,
		0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
		0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F
	         };
                
                
                
               //odczytujemy klucz z certyfikatu który jest zaszyfrowany....
                char* encrypteddMess = new char[112]; //szyfrujemy wszystko bez nagłowka...                                           
                aes256Decrypt((char*)(this->strCerKeyInstall+16), this->KeyPep,112, 32, encrypteddMess,(char*)this->strCerKeyInstall,16);        //vektor inicjujacy stanowi nagowek..                                                                                                  
                memcpy(klucz, encrypteddMess+52 -16, 32 );
                delete[] encrypteddMess;
                
                
                char L2e[16];
                char L3e[16];
                
                aes256(this->L2, klucz, 16, 32, L2e);
                aes256(this->L3, klucz, 16, 32, L3e);
               
                
                std::cout<<"\nKey 33333333............................................: ";          
                for(int m=0; m<32; m++)
                {
                  printf("%02x",   (int)((unsigned char)klucz[m] ) );            
                  std::cout<<" ";
                }  
                
               // std::cout<<"\nL2e: ";          
             //   for(int m=0; m<16; m++)
              //  {
              //    printf("%02x",   (int)((unsigned char)L2e[m] ) );            
              //    std::cout<<" ";
              //  }  
                
              //  std::cout<<"\nL3e: ";          
              //  for(int m=0; m<16; m++)
              //  {
              //    printf("%02x",   (int)((unsigned char)L3e[m] ) );            
              //    std::cout<<" ";
              //  }  
                
                
                char inputS[32];
                memcpy(inputS+0, L2e, 16);
                memcpy(inputS+16, L3e, 16);
                
               // std::cout<<"\nL2e | L3e: ";          
              //  for(int m=0; m<32; m++)
              //  {
              //    printf("%02x",   (int)((unsigned char)inputS[m] ) );            
               //   std::cout<<" ";
               // }  
                
                char keyS[32]; //klucz sesji                                
                int sizeKeyS = 0;
                                 
                SHA256(inputS, 32, keyS, &sizeKeyS);
                
              //   std::cout<<"\nKeyS ";          
               // for(int m=0; m<32; m++)
              //  {
              //    printf("%02x",   (int)((unsigned char)keyS[m] ) );            
              //    std::cout<<" ";
              //  }  
                
                
              
                 
                 memcpy(this->KeySa, keyS,16);
                 memcpy(this->KeySe, keyS+16,16);
                 
               // std::cout<<"\nKeySa ";          
               // for(int m=0; m<16; m++)
               // {
               //   printf("%02x",   (int)((unsigned char)this->KeySa[m] ) );            
               //   std::cout<<" ";
              //  } 
                
               //  std::cout<<"\nKeySe ";          
               // for(int m=0; m<16; m++)
              //  {
              //    printf("%02x",   (int)((unsigned char)this->KeySe[m] ) );            
              //    std::cout<<" ";
              //  } 
                 
                 
                 this->TimeSyg = this->Time; //czas stanowi syganture klucz asesji
                 
              //  std::cout<<"\nTime for KeySa ";                          
             //   printf("%02x",   this->TimeSyg  );            
                
                 
      
                 //testy..
                char response[50];
                memset(response,0,50);
                
                
                *type = 3; //odebranie rozkazu 2
                *sizeFrame = 44;                
                memcpy(frameReady, response, 44);
                return true;
                
      
                
               
             } //koniec rozkazu 2.....             
          
             //-----------------------------------------------------------------
             //-----------------------------------------------------------------
             
             
           }
           
           
           
            //Dane z wiadomości.................................................. 
           if(this->isCrypted) //tylko w wiadomosci syzfrowanej wystepuje podpis CMAC
           {
            //this->Mess to wartosc zaszyfrowana...
             char* decryptedMess = new char[this->MessSize];
             
             char block[16];
             memcpy(block, &this->Ctrl,2);
             memcpy(block+2,&this->NrR,2);
             memcpy(block+4,&this->TN,4);
             memset(block+8,0,7);
             memset(block+15,0,1);
                                       
             aes128Decrypt(this->Mess, this->KeySe, this->MessSize, 16, decryptedMess,(char*)block,16);        
             memcpy(this->Mess, decryptedMess, this->MessSize);
             
             delete[] decryptedMess;
               
                    
            //Nagłowek wiadomości................................................
            if(this->MessHead == NULL) delete[] this->MessHead;
            this->MessHead = new char[8]; //nagłowek niezaszyfrowany..
              
            memcpy(this->MessHead, this->Mess, 8); //skopiuj nagłowek wiadomości.. jest na poczatku wiadomosci..
                     
              
           // std::cout<<"\nDataCrypted ";   
           
            
          //  std::cout<<"\nFrame encrypted: ";          
         //   for(int m=0; m< this->MessSize; m++)
         //   {
         //     printf("%02x",   (int)((unsigned char)this->Mess[m]) );            
         //     std::cout<<" ";
         //   } 
            
          //  std::cout<<"\nHK: ";          
          //  for(int m=0; m<8; m++)
         //   {
          //    printf("%02x",   (int)((unsigned char)this->MessHead[m]) );            
           //   std::cout<<" ";
          //  } 
           
            memcpy(this->MeId, this->MessHead + 0 ,1 );
            memcpy(this->C, this->MessHead + 1 ,1 );        
            memcpy(this->Prot, this->MessHead + 2 ,2 );                       
            memcpy(&this->Time, this->MessHead + 4 ,4 );        
           
           // printf("\nMeId %02x",   (int)((unsigned char)this->MeId[0]) );            
           // printf("\nC %02x",   (int)((unsigned char)this->C[0]) );            
          //  printf("\nProt %02x",   (int)((unsigned char)this->Prot[0]) );     printf(" %02x",   (int)((unsigned char)this->Prot[1]) );                                  
          //  printf("\nTime %02x",   (int)((unsigned long)this->Time) ); std::cout<<" T2: "<<this->Time;          
    
            if(this->C[0] == 'S' && this->Prot[0] == 0 && this->Prot[1]==0 ) //sprawdz czy sygantury sie zmieniły index żądania...
            {
              //pobierz z serwera mma karty i sygnatury kart...
                                                     
                
               get_syg(  this->Install , this->karty, this->ilosc_kart, this->cardSyg, this->sygnaturyObiektow, this->ilosc_obiektow );
               
               std::cout<<"\nIlosc kart: "<<*this->ilosc_kart;
               
               
                 //sprawdz upgrade..
                 std::ifstream  confFileHandle;
                 confFileHandle.open ( "/var/www/mm_reader/KDM-C130_0v2.kfu",  std::ios::in  | std::ios::binary); 
                 if (!confFileHandle.is_open()) 
                 { 
                   std::cout<<"\n\nNie mozna utworzyc pliku KDM-C130_0v2.kfu";                    
                 }else
                 {
                   confFileHandle.seekg(0,std::ios_base::end); //przesun na koniec..
                   int size = confFileHandle.tellg();                   
                   confFileHandle.seekg(0,std::ios_base::beg); //przesun na koniec..
                   
                   confFileHandle.read( this->upgradeBuffer,  size );
                   confFileHandle.close();                        
                   
                   *this->upgadeFileSize = size;
                   
                   std::cout<<"\n\nOdczytano plik Upgrade "<<*this->upgadeFileSize;
                 }
               
                
                
               //int step = -1;
                
                repeat_syg:
                
               // step++;
                
                std::cout<<"\n\n\nOtrzymano rozkaz 'S' - sprawdz czy sygnatury sie zmienl ";
             
                
             
                short sizeResponse = 92 ; //ctrl nrr tn ctr
                char response[sizeResponse];
                 
                
                short CtrlResponse = sizeResponse;    //2 bajty     
                      CtrlResponse |= 0b0100000000000000; //14 szyfrowwniae ramki...
                      CtrlResponse |= 0b0010000000000000; //13 12 10 transjimsia w sesji inicowana przez urzadzeni
                      CtrlResponse |= 0b0000100000000000; //bit 11 nadaje komputer
                                     
                      
                short NrRResponse = this->NrR; //kolejny numer ramki..
                long  TNResponse =  this->TN;
                
                this->NrRamkiK = NrRResponse;
                
                char MessResponse[80]; // 8 nagłowka + 64 danych + 8 na podpis || 64 = 16 sygnatur czyli 16*4=64 bajty
                memcpy(MessResponse+0, this->MessHead,8);
                
                short index8 = 0; // <<----
                memcpy(MessResponse + 2, &index8,2); //zwrocenie odpowiedzi index = 8 pobranie sygnatur kart..
                //memcpy(MessResponse + 3, &index8,1); //zwrocenie odpowiedzi index = 8 pobranie sygnatur kart..
                
                long Syg = 0;
               if( *this->ilosc_kart>0 &&  (*this->cardSyg)  != 0 &&  (*this->cardSyg)>0 ) Syg = (*this->cardSyg);   // 
            
                
                //memset(MessResponse+8,0,16 * 4); //16 sygnatur po 32 bity (4 bajty)
                memset(MessResponse+8,0, 8 * 4); // 8 pierwszych syugnatur to 0
             
                
                if(*this->ilosc_kart>0)
                {
                       // std::cout<<"\nAktualna sygnatura kart: "<< (*this->cardSyg) <<"\n";
                }else
                {
                  //  std::cout<<"\nBrak kart.............";
                }
                
                memset(MessResponse+40,0, 1 * 4); // 8 pierwszych syugnatur to 0 <<<< -- ta jest zmienna.... jesli coś zmieni się w kartach..
                    if( (*this->cardSyg)  != 0 && (*this->cardSyg)>0 && *this->ilosc_kart>0 )  memcpy(MessResponse+40,this->cardSyg , 1 * 4); //zmieniła się sygnatura kard
                   
                memset(MessResponse+44,0, 7 * 4); // 8 pierwszych syugnatur to 0
                
                
                //dodaj syganture upgrade..                                
                //odczyta sygnature z pliku..
                unsigned long sygUpdate = 0;
                               
                if( *this->upgadeFileSize > 1024) //jakis plik z aktualizacja został załadowany..
                {
                    memcpy(&sygUpdate, this->upgradeBuffer+12,4);
                    
                    memcpy(MessResponse+12, &sygUpdate, 4); // dodaj syganture upgrade.
                    
                    Syg = std::max( (double)sygUpdate, (double)Syg); //zmianiały dodatkowo sygnature globalna od upgrade...
                    
                  //  std::cout<<"\n\nSygantura Upgrade: "<<sygUpdate;
                }                
                
                //koniec upgrade...
                
                
                //sygantury konfiguracji.....
                
              //    std::cout<<"\nOdczyt sygnatury grupy nr 0, 16 obiektow..konfiguracja";
                
                unsigned long sygGrupa0 = 0;
                for(int obj=0; obj<16; obj++)
                {
                  unsigned long sygOut = 0;
                  int sizeOut;
                  char buffSyg[1024 * 50];
                  
                  if(odczytajObiekt( 0, obj, &sygOut, buffSyg, &sizeOut, 1024 * 50))
                  {
                     // std::cout<<"\nOdczytano syganture Grupy 0 Obiekt "<<obj<<"  = "<<sygOut;
                      sygGrupa0 = std::max( sygOut,sygGrupa0 );                     
                  }
                }
                Syg =  std::max( (double)sygGrupa0, (double)Syg);
                memcpy(MessResponse+8, &sygGrupa0, 4); // dodaj syganture grupy 4
                
                
                
               // std::cout<<"\nOdczyt sygnatury grupy nr 4, 16 obiektow..konfiguracja";
                
                unsigned long sygGrupa4 = 0;
                for(int obj=0; obj<16; obj++)
                {
                  unsigned long sygOut = 0;
                  int sizeOut;
                  char buffSyg[1024 * 50];
                  
                  if(odczytajObiekt( 4, obj, &sygOut, buffSyg, &sizeOut, 1024 * 50))
                  {
                   //   std::cout<<"\nOdczytano syganture Grupy 4 Obiekt "<<obj<<"  = "<<sygOut;
                     sygGrupa4 = std::max( sygOut,sygGrupa4 );                               
                  }
                }
                Syg =  std::max((double)sygGrupa4, (double)Syg);
                memcpy(MessResponse+8+16, &sygGrupa4, 4); // dodaj syganture grupy 4
                
                
              //  std::cout<<"\nOdczyt sygnatury grupy nr 5, 16 obiektow..harmonogramy";
                
                unsigned long sygGrupa5 = 0;
                for(int obj=0; obj<16; obj++)
                {
                  unsigned long sygOut = 0;
                  int sizeOut;
                  char buffSyg[1024 * 50];
                  
                  if(odczytajObiekt( 5, obj, &sygOut, buffSyg, &sizeOut, 1024 * 50))
                  {
                     // std::cout<<"\nOdczytano syganture Grupy 5 Obiekt "<<obj<<"  = "<<sygOut;
                      sygGrupa5 = std::max( sygOut,sygGrupa5 );  
                  }
                }
                
                Syg =  std::max((double)sygGrupa5, (double)Syg);
                memcpy(MessResponse+8+20, &sygGrupa5, 4); // dodaj syganture grupy 5
                
                
                // std::cout<<"\nOdczyt sygnatury grupy nr 6, 16 obiektow..prawa dostepu";
                
                unsigned long sygGrupa6 = 0;
                for(int obj=0; obj<16; obj++)
                {
                  unsigned long sygOut = 0;
                  int sizeOut;
                  char buffSyg[1024 * 50];
                  
                  if(odczytajObiekt( 6, obj, &sygOut, buffSyg, &sizeOut, 1024 * 50))
                  {
                    //  std::cout<<"\nOdczytano syganture Grupy 5 Obiekt "<<obj<<"  = "<<sygOut;
                       sygGrupa6 = std::max( sygOut,sygGrupa6 );  
                  }
                }
                Syg =  std::max((double)sygGrupa6, (double)Syg);
                memcpy(MessResponse+8+24, &sygGrupa6, 4); // dodaj syganture grupy 5
                
                
                //koniec sygantur konfiguracji...
                
                
                
                //ustaw syganture globalną..                                            
                memcpy(MessResponse+8, &Syg,4); //sygnatura zerowa - glowan
                memcpy(MessResponse+4, &Syg,4); //sygnatura oboektu
                //memcpy(MessResponse+8, &Syg,4); //sygnatura globalna.. ?? nie wiem czy ja ustawiac..
                
                
                
             //   std::cout<<"\n\nMessResponse bez podpisu: ";          
              //  for(int m=0; m<72; m++)
              //  {
              //    printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
               //  std::cout<<" ";
               // }
                
                char ciagDoPodpisu[80];               
                memcpy(ciagDoPodpisu+0, &CtrlResponse,2);
                memcpy(ciagDoPodpisu+2, &NrRResponse,2);
                memcpy(ciagDoPodpisu+4, &TNResponse,4);
                memcpy(ciagDoPodpisu+8, MessResponse,72); // 8 + 64
               
                
              
              // std::cout<<"\n\nCiag do wyliczenia podpisu ";          
              // for(int m=0; m<80; m++)
              // {
              //   printf("%02x",   (int)((unsigned char)ciagDoPodpisu[m]) );            
              //   std::cout<<" ";
              // }
          
                              
               
               char bufferCMac[1024];
               memset(bufferCMac,0,1024);
               int sizeCMac = 0;
               createCMAC(ciagDoPodpisu,this->KeySa,80,16, bufferCMac, &sizeCMac);
             
              
               
               
            //   std::cout<<"\n\nCMAC ";          
             //  for(int m=0; m<sizeCMac; m++)
             //  {
              //   printf("%02x",   (int)((unsigned char)bufferCMac[m]) );            
              //   std::cout<<" ";
              // }
               
                       
               
               memcpy(MessResponse+72,bufferCMac,8); //tylko pierwsze osiem
               
             //  std::cout<<"\n\nCiag podpisany: ";          
             //  for(int m=0; m<80; m++)
             //  {
             //    printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
              //   std::cout<<" ";
              // }
                        
                              
               //zaszyfrouj..
               
                char block[16];
                memcpy(block, &CtrlResponse,2);
                memcpy(block+2,&NrRResponse,2);
                memcpy(block+4,&TNResponse,4);
                memset(block+8,0,7);
                memset(block+15,0,1);
                
                
              //  std::cout<<"\n\nBlok danych dal CTR: ";          
              // for(int m=0; m<16; m++)
              // {
              //   printf("%02x",   (int)((unsigned char)block[m]) );            
              //   std::cout<<" ";
              // }
               
               char encrypted[80];
               //aes128Encrypt(MessResponse, this->KeySa, 88, 16,encrypted, block, 16);
               aes128Encrypt(MessResponse, this->KeySe, 80, 16,encrypted, block, 16);
               
               memcpy(MessResponse, encrypted,80);
              
            //  std::cout<<"\n\nCiag podpisany i zaszyfrowany: ";          
             //  for(int m=0; m<80; m++)
              // {
              //   printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
              //   std::cout<<" ";
              // }
               
               
               
               memcpy(response+0,&CtrlResponse,2);
               memcpy(response+2,&NrRResponse,2);
               memcpy(response+4,&TNResponse,4);
               memcpy(response+8,MessResponse,80);
               
                              
               unsigned int crc = crc32b(response, 88);
                       
               memcpy(response+88,&crc,4);//odpowiedz bez nagówka ramki
               
             
              // std::cout<<"\n\nResponse ";          
              // for(int m=0; m<92; m++)
             //  {
             //    printf("%02x",   (int)((unsigned char)response[m]) );            
             //    std::cout<<" ";
             //  }
                     
               
                *type = 4; //wyslano w klasie...                
                
                write(this->socket , response ,92  );
                
             
                sleep(3);
                
                return true;                                
        
                
            }
           
            
            if(this->C[0] == 'S' && this->Prot[0] == 8 && this->Prot[1]==0 ) //pobranie sygnatur kart....
            {
            
                
                std::cout<<"\n\n\nOtrzymano rozkaz 'S 8' - zadanie przeslania sygnatur kart";
             
                
             
                short sizeResponse = 1052 ; //ctrl nrr tn ctr
                char response[sizeResponse];
                 
                
                short CtrlResponse = sizeResponse;    //2 bajty     
                      CtrlResponse |= 0b0100000000000000; //14 szyfrowwniae ramki...
                      CtrlResponse |= 0b0010000000000000; //13 12 10 transjimsia w sesji inicowana przez urzadzeni
                      CtrlResponse |= 0b0000100000000000; //bit 11 nadaje komputer
                                     
                      
                short NrRResponse = this->NrR; //kolejny numer ramki..
                long  TNResponse =  this->TN;
                
                this->NrRamkiK = NrRResponse;
                
                char MessResponse[2080]; // 8 nagłowka + 64 danych + 8 na podpis || 64 = 16 sygnatur czyli 16*4=64 bajty
                memcpy(MessResponse+0, this->MessHead,8);
                
               // short index8 = 0; // <<----
               // memcpy(MessResponse + 2, &index8,2); //zwrocenie odpowiedzi index = 8 pobranie sygnatur kart..
                //memcpy(MessResponse + 3, &index8,1); //zwrocenie odpowiedzi index = 8 pobranie sygnatur kart..
                
                long Syg = 0;
                Syg = (*this->cardSyg);   // 
                
                std::cout<<"\n\nSYGGGGGGGG: "<<(*this->cardSyg)<<"\n\n";
                                        
                memcpy(MessResponse+4, &Syg,4); //sygnatura oboektu
                
               
                //dane
                //memset(MessResponse+8,0,16 * 4); //16 sygnatur po 32 bity (4 bajty)
                                     
                //wyzeruj obiekty...
                memset(MessResponse+8,0, 256 * 4);  //(00 00 00 00) * 255 - pozostałe 255 sygnatur obiektów, w których nie była jeszcze zapisana karta.
             
                int offsetObj = 0;
                for(int st=0; st<*this->ilosc_obiektow; st++)
                {                  
                    memcpy( MessResponse+8 + offsetObj, &this->sygnaturyObiektow[st] ,  4);
                    
                      std::cout<<"\nSyg ob "<<st<<" = "<< this->sygnaturyObiektow[st] ;
                    
                    offsetObj += 4;
                }
                
                
                std::cout<<"\n\nMessResponse bez podpisu: ";          
                for(int m=0; m<1032; m++)
                {
                  printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
                 std::cout<<" ";
                }
                
                char ciagDoPodpisu[2080];               
                memcpy(ciagDoPodpisu+0, &CtrlResponse,2);
                memcpy(ciagDoPodpisu+2, &NrRResponse,2);
                memcpy(ciagDoPodpisu+4, &TNResponse,4);
                memcpy(ciagDoPodpisu+8, MessResponse,1032); // 8 + 64
               
                
              
              // std::cout<<"\n\nCiag do wyliczenia podpisu ";          
              // for(int m=0; m<1040; m++)
              // {
              //   printf("%02x",   (int)((unsigned char)ciagDoPodpisu[m]) );            
              //   std::cout<<" ";
             //  }
          
                              
               
               char bufferCMac[2024];
               memset(bufferCMac,0,2024);
               int sizeCMac = 0;
               createCMAC(ciagDoPodpisu,this->KeySa,1040,16, bufferCMac, &sizeCMac);
             
              
               
               
              // std::cout<<"\n\nCMAC ";          
              // for(int m=0; m<sizeCMac; m++)
              // {
              //   printf("%02x",   (int)((unsigned char)bufferCMac[m]) );            
              //   std::cout<<" ";
             //  }
             //  
                       
               
               memcpy(MessResponse+1032,bufferCMac,8); //tylko pierwsze osiem
               
              // std::cout<<"\n\nCiag podpisany: ";          
              // for(int m=0; m<1040; m++)
              // {
              //   printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
              //   std::cout<<" ";
              // }
                        
                              
               //zaszyfrouj..
               
                char block[16];
                memcpy(block, &CtrlResponse,2);
                memcpy(block+2,&NrRResponse,2);
                memcpy(block+4,&TNResponse,4);
                memset(block+8,0,7);
                memset(block+15,0,1);
                
                
             //   std::cout<<"\n\nBlok danych dal CTR: ";          
              // for(int m=0; m<16; m++)
             //  {
             //    printf("%02x",   (int)((unsigned char)block[m]) );            
             //    std::cout<<" ";
             //  }
               
               char encrypted[2080];
               //aes128Encrypt(MessResponse, this->KeySa, 88, 16,encrypted, block, 16);
               aes128Encrypt(MessResponse, this->KeySe, 1040, 16,encrypted, block, 16);
               
               memcpy(MessResponse, encrypted,1040);
              
             //  std::cout<<"\n\nCiag podpisany i zaszyfrowany: ";          
             //  for(int m=0; m<1040; m++)
             //  {
             //    printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
             //    std::cout<<" ";
             //  }
               
               
               
               memcpy(response+0,&CtrlResponse,2);
               memcpy(response+2,&NrRResponse,2);
               memcpy(response+4,&TNResponse,4);
               memcpy(response+8,MessResponse,1040);
               
                              
               unsigned int crc = crc32b(response, 1048);
                       
               memcpy(response+1048,&crc,4);//odpowiedz bez nagówka ramki
               
             
              // std::cout<<"\n\nResponse ";          
              // for(int m=0; m<1052; m++)
             //  {
              //   printf("%02x",   (int)((unsigned char)response[m]) );            
              //   std::cout<<" ";
             //  }
                     
               
                *type = 4; //wyslano w klasie...                
                
                write(this->socket , response ,1052  );
                
             
                
                return true;
               
               std::cout<<"\n\n\n";
            }
            
        
    
            if(this->C[0] == 'S' && (!(this->Prot[0] == 8 && this->Prot[1]==0)) ) //pobranie sygnatur konfiguracji
            {
            
                char Grupa = 0; //numer obiektu..
               char Index = 0; //numer obiektu..
               memcpy(&Index, this->MessHead + 3 ,1 );    
               memcpy(&Grupa, this->MessHead + 2 ,1 );  
                                         
               
               std::cout<<"\n\n\nOtrzymano rozkaz 'S != 8' - rzadanie przeslania sygnatur";
             
                
             
                short sizeResponse = 92 ; //ctrl nrr tn ctr
                char response[sizeResponse];
                 
                
                short CtrlResponse = sizeResponse;    //2 bajty     
                      CtrlResponse |= 0b0100000000000000; //14 szyfrowwniae ramki...
                      CtrlResponse |= 0b0010000000000000; //13 12 10 transjimsia w sesji inicowana przez urzadzeni
                      CtrlResponse |= 0b0000100000000000; //bit 11 nadaje komputer
                                     
                      
                short NrRResponse = this->NrR; //kolejny numer ramki..
                long  TNResponse =  this->TN;
                
                this->NrRamkiK = NrRResponse;
                
                char MessResponse[2080]; // 8 nagłowka + 64 danych + 8 na podpis || 64 = 16 sygnatur czyli 16*4=64 bajty
                memcpy(MessResponse+0, this->MessHead,8);
                
               // short index8 = 0; // <<----
               // memcpy(MessResponse + 2, &index8,2); //zwrocenie odpowiedzi index = 8 pobranie sygnatur kart..
                //memcpy(MessResponse + 3, &index8,1); //zwrocenie odpowiedzi index = 8 pobranie sygnatur kart..
                
                long Syg = 0;
               
               
                memset(MessResponse+8,0, 64);  //16 x 0x00
                
                std::cout<<"\nOdczyt sygnatury  obiektow z grupy "<<(int)Grupa<<" Obiekt "<<(int)Index;
                
                unsigned long sygGrupaX = 0;
                for(int obj=0; obj<16; obj++)
                {
                  unsigned long sygOut = 0;
                  int sizeOut;
                  char buffSyg[1024 * 50];
                  
                  if(odczytajObiekt( Grupa, obj, &sygOut, buffSyg, &sizeOut, 1024 * 50))
                  {
                      std::cout<<"\nOdczytano syganture Grupy "<<(int)Grupa<<" Obiekt "<<(int)obj<<"  = "<<(int)sygOut;
                      sygGrupaX = std::max( (double)sygOut,(double)sygGrupaX);
                      
                      int numS = 4 * obj;
                      memcpy(MessResponse+8 + numS, &sygOut,4); //sygnatura obiektu nur obj..
                  }
                }
                
                
                Syg = std::max( (double)sygGrupaX, (double)Syg );                                        
                memcpy(MessResponse+4, &Syg,4); //sygnatura oboektu             
                
                
                std::cout<<"\n\nMessResponse bez podpisu: ";          
                for(int m=0; m<72; m++)
                {
                 printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
                 std::cout<<" ";
                }
                
                char ciagDoPodpisu[2080];               
                memcpy(ciagDoPodpisu+0, &CtrlResponse,2);
                memcpy(ciagDoPodpisu+2, &NrRResponse,2);
                memcpy(ciagDoPodpisu+4, &TNResponse,4);
                memcpy(ciagDoPodpisu+8, MessResponse,72); // 
               
                
              
              // std::cout<<"\n\nKlucz do podpisu ";          
              // for(int m=0; m<16; m++)
              // {
               //  printf("%02x",   (int)((unsigned char)this->KeySa[m]) );            
              //   std::cout<<" ";
              // }
          
                              
               
               char bufferCMac[2024];
               memset(bufferCMac,0,2024);
               int sizeCMac = 0;
               createCMAC(ciagDoPodpisu,this->KeySa,80,16, bufferCMac, &sizeCMac);
               
     
             
              
               
               
              // std::cout<<"\n\nCMAC ";          
             //  for(int m=0; m<sizeCMac; m++)
             //  {
               //  printf("%02x",   (int)((unsigned char)bufferCMac[m]) );            
               // std::cout<<" ";
               //}
                                      
               
               memcpy(MessResponse+72,bufferCMac,8); //tylko pierwsze osiem
               
              // std::cout<<"\n\nCiag podpisany: ";          
              // for(int m=0; m<80; m++)
              // {
               //  printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
               //  std::cout<<" ";
               //}
                        
                              
               //zaszyfrouj..
               
                char block[16];
                memcpy(block, &CtrlResponse,2);
                memcpy(block+2,&NrRResponse,2);
                memcpy(block+4,&TNResponse,4);
                memset(block+8,0,7);
                memset(block+15,0,1);
                
                
             //   std::cout<<"\n\nBlok danych dal CTR: ";          
              // for(int m=0; m<16; m++)
             //  {
             //    printf("%02x",   (int)((unsigned char)block[m]) );            
             //    std::cout<<" ";
             //  }
               
               char encrypted[2080];
               //aes128Encrypt(MessResponse, this->KeySa, 88, 16,encrypted, block, 16);
               aes128Encrypt(MessResponse, this->KeySe, 80, 16,encrypted, block, 16);
               
               memcpy(MessResponse, encrypted,80);
              
             //  std::cout<<"\n\nCiag podpisany i zaszyfrowany: ";          
             //  for(int m=0; m<1040; m++)
             //  {
             //    printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
             //    std::cout<<" ";
             //  }
               
               
               
               memcpy(response+0,&CtrlResponse,2);
               memcpy(response+2,&NrRResponse,2);
               memcpy(response+4,&TNResponse,4);
               memcpy(response+8,MessResponse,80);
               
                              
               unsigned int crc = crc32b(response, 88);
                       
               memcpy(response+88,&crc,4);//odpowiedz bez nagówka ramki
               
             
              // std::cout<<"\n\nResponse ";          
              // for(int m=0; m<1052; m++)
             //  {
              //   printf("%02x",   (int)((unsigned char)response[m]) );            
              //   std::cout<<" ";
             //  }
                     
               
                *type = 4; //wyslano w klasie...                
                
                write(this->socket , response ,92  );
                
             
                
                return true;
               
               std::cout<<"\n\n\n";
            }
            
        
            
            
            if(this->C[0] == 'P'  ) //polecenie zapisania konfiguracji urzadzenia na dysku..
            {
              //pobierz z serwera mm karty i sygnatury kart...
          
               // step++;
                           
             
                
               char Grupa = 0; //numer obiektu..
               char Index = 0; //numer obiektu..
               memcpy(&Index, this->MessHead + 2 ,1 );    
               memcpy(&Grupa, this->MessHead + 3 ,1 );  
               
               unsigned long SygnaturObiektu = 0;
               memcpy(&SygnaturObiektu, this->MessHead + 4 ,4 );      
               
                 std::cout<<"\n\n\nOtrzymano rozkaz 'p' - zapisz konfiguracje, Grp "<<(int)Grupa<<" Obj "<<(int)Index<<", sygantura "<<SygnaturObiektu;
               
               
               char Cack = 0; //potwierdzenie zapisania danych...
               
                            
             
                
                int iloscDanych = this->MessSize -8 - 8; //-8 nagłowka i - 8 cmac..
              
                
                std::cout<<"\nIlosc danych: "<<iloscDanych<<"\n";
                
                char* tmpBufConfiguration = new char[iloscDanych+20]; //bity 13-16 to sygantuar oboiektu, jak w upgrade..
                memset(tmpBufConfiguration,0,iloscDanych+20 );
                memcpy(tmpBufConfiguration+12, &SygnaturObiektu ,4); //zapis suganture obiektu od 13bajtu
                memcpy(tmpBufConfiguration+16, this->Mess+8,iloscDanych); //
                     
                 //tutaujjjjjjj...
                  std::string confInstall = "/var/www/mm_reader/configuration/";
                  confInstall.append( gxh_LongToString(this->TN) );
                  confInstall.append("_grp_");
                  confInstall.append( gxh_LongToString( (unsigned long)Grupa) ); //grupa obiektu
                  confInstall.append("_obj_");
                  confInstall.append( gxh_LongToString( (unsigned long)Index) ); //grupa obiektu
                  confInstall.append(".conf");
                
                  
                  std::ofstream confInstallHandle;
                  confInstallHandle.open ( confInstall.c_str(),  std::ofstream::binary); 
                  if(confInstallHandle.is_open())
                  {
                    confInstallHandle.write((char*)tmpBufConfiguration, iloscDanych+16 );
                    confInstallHandle.close();
                    
                    Cack = 0x06; //zapisano <<<--------------
                  }
                
                delete[] tmpBufConfiguration;
                
                
             
                short sizeResponse = 28 ; //ctrl nrr tn ctr ACK = 1 bajt
                char response[sizeResponse];
                 
                
                short CtrlResponse = sizeResponse;    //2 bajty     
                      CtrlResponse |= 0b0100000000000000; //14 szyfrowwniae ramki...
                      CtrlResponse |= 0b0010000000000000; //13 12 10 transjimsia w sesji inicowana przez urzadzeni
                      CtrlResponse |= 0b0000100000000000; //bit 11 nadaje komputer
                                     
                      
                short NrRResponse = this->NrR; //kolejny numer ramki..
                long  TNResponse =  this->TN;
                
                this->NrRamkiK = NrRResponse;
                
                char MessResponse[80]; // 8 nagłowka + 64 danych + 8 na podpis || 64 = 16 sygnatur czyli 16*4=64 bajty
                memcpy(MessResponse+0, this->MessHead,8);
                
             
                memcpy(MessResponse + 1, &Cack,1); //// 0x06
                
                short index = 0; // <<----
                memcpy(MessResponse + 2, &index,2); //zwrocenie odpowiedzi index = 8 pobranie sygnatur kart..
                //memcpy(MessResponse + 3, &index8,1); //zwrocenie odpowiedzi index = 8 pobranie sygnatur kart..
                
                long Syg = 0;
               if( (*this->cardSyg)  != 0 &&  (*this->cardSyg)>0 ) Syg = (*this->cardSyg);   // 
                                        
                memcpy(MessResponse+4, &Syg,4); //sygnatura oboektu
                
                //memset(MessResponse+8,0,16 * 4); //16 sygnatur po 32 bity (4 bajty)             
              
            
                
             //   std::cout<<"\n\nMessResponse bez podpisu: ";          
              //  for(int m=0; m<72; m++)
              //  {
              //    printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
               //  std::cout<<" ";
               // }
                
                char ciagDoPodpisu[80];               
                memcpy(ciagDoPodpisu+0, &CtrlResponse,2);
                memcpy(ciagDoPodpisu+2, &NrRResponse,2);
                memcpy(ciagDoPodpisu+4, &TNResponse,4);
                memcpy(ciagDoPodpisu+8, MessResponse,8); // 8 + 64
               
                
              
              // std::cout<<"\n\nCiag do wyliczenia podpisu ";          
              // for(int m=0; m<80; m++)
              // {
              //   printf("%02x",   (int)((unsigned char)ciagDoPodpisu[m]) );            
              //   std::cout<<" ";
              // }
          
                              
               
               char bufferCMac[1024];
               memset(bufferCMac,0,1024);
               int sizeCMac = 0;
               createCMAC(ciagDoPodpisu,this->KeySa,16,16, bufferCMac, &sizeCMac);
             
              
               
               
            //   std::cout<<"\n\nCMAC ";          
             //  for(int m=0; m<sizeCMac; m++)
             //  {
              //   printf("%02x",   (int)((unsigned char)bufferCMac[m]) );            
              //   std::cout<<" ";
              // }
               
                       
               
               memcpy(MessResponse+8,bufferCMac,8); //tylko pierwsze osiem
               
             //  std::cout<<"\n\nCiag podpisany: ";          
             //  for(int m=0; m<80; m++)
             //  {
             //    printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
              //   std::cout<<" ";
              // }
                        
                              
               //zaszyfrouj..
               
                char block[16];
                memcpy(block, &CtrlResponse,2);
                memcpy(block+2,&NrRResponse,2);
                memcpy(block+4,&TNResponse,4);
                memset(block+8,0,7);
                memset(block+15,0,1);
                
                
              //  std::cout<<"\n\nBlok danych dal CTR: ";          
              // for(int m=0; m<16; m++)
              // {
              //   printf("%02x",   (int)((unsigned char)block[m]) );            
              //   std::cout<<" ";
              // }
               
               char encrypted[80];
               //aes128Encrypt(MessResponse, this->KeySa, 88, 16,encrypted, block, 16);
               aes128Encrypt(MessResponse, this->KeySe, 16, 16,encrypted, block, 16);
               
               memcpy(MessResponse, encrypted,16);
              
            //  std::cout<<"\n\nCiag podpisany i zaszyfrowany: ";          
             //  for(int m=0; m<80; m++)
              // {
              //   printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
              //   std::cout<<" ";
              // }
               
               
               
               memcpy(response+0,&CtrlResponse,2);
               memcpy(response+2,&NrRResponse,2);
               memcpy(response+4,&TNResponse,4);
               memcpy(response+8,MessResponse,16);
               
                              
               unsigned int crc = crc32b(response, 24);
                       
               memcpy(response+24,&crc,4);//odpowiedz bez nagówka ramki
               
             
              // std::cout<<"\n\nResponse ";          
              // for(int m=0; m<92; m++)
             //  {
             //    printf("%02x",   (int)((unsigned char)response[m]) );            
             //    std::cout<<" ";
             //  }
                     
               
                *type = 4; //wyslano w klasie...                
                
                write(this->socket , response ,28  );
                
             
                
                return true;
               
               std::cout<<"\n\n\n";
                
            }
          
            
             if(this->C[0] == 'G'   ) //pobranie obiekutow...
             {
                                    
               unsigned char Grupa = 0; //numer obiektu..
               unsigned char Index = 0; //numer obiektu..
               memcpy(&Index, this->MessHead + 2 ,1 );    
               memcpy(&Grupa, this->MessHead + 3 ,1 );    
               
                 
               std::cout<<"\n\n\n\n\n---- roazka O grupa "<<(int)Grupa<<" index "<<(int)Index<<" \n";
               
               int SygGrup = 0;
               
               if(Grupa == 8)
               {
                  
                   int grupaStart = 0;
                   int grupaStop  = 128;
                   
                   if(Index >0 ) // np .1
                   {
                         grupaStart += 128;
                         grupaStop  += 128;
                         SygGrup += 4;
                   }
                   
                   if(Index >1 ) // np .1
                   {
                         grupaStart += 128;
                         grupaStop  += 128;
                         
                         SygGrup += 4;
                   }
                   
                   //**
                     if(Index >2 ) // np .1
                   {
                         grupaStart += 128;
                         grupaStop  += 128;
                         
                         SygGrup += 4;
                   }
                   
                      if(Index >3 ) // np .1
                   {
                         grupaStart += 128;
                         grupaStop  += 128;
                         
                         SygGrup += 4;
                   }
                   
                   if(Index >4 ) // np .1
                   {
                         grupaStart += 128;
                         grupaStop  += 128;
                         
                         SygGrup += 4;
                   }
                   
                   //****
                   
                   
                  int grupInc = -1; 
                  
                  std::cout<<"\nGrupa O 8,  index: "<<Index<<" start: "<<grupaStart<<" stop: "<<grupaStop<<"\n";  
                   
                   std::cout<<"\nwysylam dane kart.... \n";
                  //nalezy wysłać 4 ramki po 32 karty...                                             
                  for(int c=grupaStart; c<grupaStop; c+=32) //wysyłam pod 32 karty....
                  {
                      
                      grupInc++;
                        
                        std::cout<<"\n\nSeria kard "<<c<<"\n";
                        
                      
                                                               
                       
                        short sizeResponse = 1404 ; // 
                        char response[sizeResponse];
                 
                
                        short CtrlResponse = sizeResponse;    //2 bajty     
                              CtrlResponse |= 0b0100000000000000; //14 szyfrowwniae ramki...
                              CtrlResponse |= 0b0010000000000000; //13 12 10 transjimsia w sesji inicowana przez urzadzeni
                              CtrlResponse |= 0b0000100000000000; //bit 11 nadaje komputer
                                     
                      
                              short NrRResponse = this->NrR; //kolejny numer ramki..
                              long  TNResponse =  this->TN;
                
                              this->NrRamkiK = NrRResponse;
                
                              char MessResponse[2080];  
                              memcpy(MessResponse+0, this->MessHead,8);
                              
                              char Cr = 'G';
                              memcpy(MessResponse+1, &Cr,1); 
                
                                      
                              unsigned char GrupaX = (16*grupInc) + Grupa;
                              unsigned char IndexX = Index; 
                              memcpy(MessResponse + 2, &IndexX, 1 );    
                              memcpy( MessResponse+ 3,&GrupaX  ,1 ); 
                              
                              
                              
                              
                              long Syg = 0;
                              Syg = (*this->cardSyg);   //                               
                              Syg = Syg - SygGrup;                                                      
                              memcpy(MessResponse+4, &Syg,4); //sygnatura oboektu
                              
                              
                              //??????????????
                              memcpy(MessResponse+4, &this->sygnaturyObiektow[Index],4); //sygnatura oboektu
                              
                              std::cout<<"\nSygantura tego obiektu "<<(int)(this->sygnaturyObiektow[Index]);
                              
                              
                
                              //dane                
                              int startIndex = 8;
                              for(int mm=0; mm<32; mm++)
                              {
                               memcpy(MessResponse + startIndex, this->karty[c + mm].card ,43); //kopiuj do danych dane kart..
                               startIndex += 43;
                              }
             
            
                
                
                              std::cout<<"\n\nMessResponse Karty bez podpisu: ";          
                              for(int m=0; m<1384; m++)
                              //for(int m=0; m<9; m++)
                              {
                                printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
                                std::cout<<" ";
                              }
                
                             char ciagDoPodpisu[2080];               
                             memcpy(ciagDoPodpisu+0, &CtrlResponse,2);
                             memcpy(ciagDoPodpisu+2, &NrRResponse,2);
                             memcpy(ciagDoPodpisu+4, &TNResponse,4);
                             memcpy(ciagDoPodpisu+8, MessResponse,1384); // 8 + 32 * 43
               
                
              
                         //   std::cout<<"\n\nCiag do wyliczenia podpisu ";          
                         //   for(int m=0; m<1392; m++)
                           //  {
                           //    printf("%02x",   (int)((unsigned char)ciagDoPodpisu[m]) );            
                            //   std::cout<<" ";
                          //   }
          
                              
               
                            char bufferCMac[2024];
                            memset(bufferCMac,0,2024);
                            int sizeCMac = 0;
                            createCMAC(ciagDoPodpisu,this->KeySa,1392,16, bufferCMac, &sizeCMac);
             
              
               
               
                           // std::cout<<"\n\nCMAC ";          
                           // for(int m=0; m<sizeCMac; m++)
                           // {
                           //     printf("%02x",   (int)((unsigned char)bufferCMac[m]) );            
                           //     std::cout<<" ";
                          //  }         
               
                       
               
                            memcpy(MessResponse+1384,bufferCMac,8); //tylko pierwsze osiem
               
                          //  std::cout<<"\n\nCiag podpisany: ";          
                          //  for(int m=0; m<1392; m++)
                          //  {
                            //  printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
                           //   std::cout<<" ";
                           // }
                        
                              
                            //zaszyfrouj..
               
                            char block[16];
                            memcpy(block, &CtrlResponse,2);
                            memcpy(block+2,&NrRResponse,2);
                            memcpy(block+4,&TNResponse,4);
                            memset(block+8,0,7);
                            memset(block+15,0,1);
                
                
                          //  std::cout<<"\n\nBlok danych dal CTR: ";          
                          //  for(int m=0; m<16; m++)
                              // {
                             //      printf("%02x",   (int)((unsigned char)block[m]) );            
                              //     std::cout<<" ";
                              // }
               
                               char encrypted[2080];
                               //aes128Encrypt(MessResponse, this->KeySa, 88, 16,encrypted, block, 16);
                              aes128Encrypt(MessResponse, this->KeySe, 1392, 16,encrypted, block, 16);
               
                              memcpy(MessResponse, encrypted,1392);
              
                            //  std::cout<<"\n\nCiag podpisany i zaszyfrowany: ";          
                            //  for(int m=0; m<1392; m++)
                              //    {
                               //      printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
                                //     std::cout<<" ";
                                //  }
               
               
               
                                  memcpy(response+0,&CtrlResponse,2);
                                  memcpy(response+2,&NrRResponse,2);
                                  memcpy(response+4,&TNResponse,4);
                                  memcpy(response+8,MessResponse,1392);
               
                              
                                 unsigned int crc = crc32b(response, 1400);
                       
                                 memcpy(response+1400,&crc,4);//odpowiedz bez nagówka ramki
               
             
                             //   std::cout<<"\n\nResponse ";          
                              //  for(int m=0; m<1404; m++)
                              //  {
                              //   printf("%02x",   (int)((unsigned char)response[m]) );            
                              //   std::cout<<" ";
                              //  }
                     
               
                                *type = 4; //wyslano w klasie...                
                
                               write(this->socket , response ,1404  );
                               usleep(1000 * 1000); //5 ms wait for data  
                      
                      
                      
                  } //koniec petli for z kartami...                 
               }//koniec kart..
              
               
               if(Grupa != 8 ) //nie karty i nie upgrade..
               {
                   std::cout<<"\nwysylam dane obiektu.."<<Grupa<<". \n";       
                   
                   char buffFile[2000*50];
                   int sizeFile = 0;
                   
                   long Syg = 0;
              
                  
                   
                  
                  if(odczytajObiekt( Grupa, Index, &Syg, buffFile, &sizeFile, 1024 * 50))
                  {
                      std::cout<<"\nOdczytano syganture Grupy "<< (int)Grupa<<" obj "<<(int)Index<<" =  "<<Syg;                        
                  }                                   
                    
                   if(sizeFile < 2)
                   {
                       std::cout<<"\nNie odczytano plik konfiguracji!!!!!!!!!!!!!! rozmiar: "<<sizeFile<<"-16 nagowka... \n";  
                       return false;
                   }
                                                           
                       
                        short sizeResponse = 8 + 8 + (sizeFile) + 8 + 4 ; // 
                        char response[2000]; //a co tam...
                 
                
                        short CtrlResponse = sizeResponse;    //2 bajty     
                              CtrlResponse |= 0b0100000000000000; //14 szyfrowwniae ramki...
                              CtrlResponse |= 0b0010000000000000; //13 12 10 transjimsia w sesji inicowana przez urzadzeni
                              CtrlResponse |= 0b0000100000000000; //bit 11 nadaje komputer
                                     
                      
                              short NrRResponse = this->NrR; //kolejny numer ramki..
                              long  TNResponse =  this->TN;
                
                              this->NrRamkiK = NrRResponse;
                
                              char MessResponse[2080];  
                              memcpy(MessResponse+0, this->MessHead,8);
                              
                              char Cr = 'G';
                              memcpy(MessResponse+1, &Cr,1); 
                
                          
                              //short indeX = Index;                                                 
                             // memcpy(MessResponse+2, &indeX,2); //sygnatura oboektu
                              
                        
                
                            //  std::cout<<"\n\nSygnatura: "<<(*this->cardSyg)<<"\n\n";
                                        
                              memcpy(MessResponse+4, &Syg,4); //sygnatura oboektu
                
                              //dane                
                             
                              //tutu2019...
                               //memcpy(MessResponse + 8,  buffFile+16  ,(sizeFile)); //kopiuj do danych dane kart..
                               memcpy(MessResponse + 8,  buffFile  ,(sizeFile)); //kopiuj do danych dane kart..
                              
            
                
                
                           //   std::cout<<"\n\nMessResponse bez podpisu: ";          
                            //  for(int m=0; m<1384; m++)
                             // {
                             //   printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
                             //   std::cout<<" ";
                            //  }
                
                             char ciagDoPodpisu[2080];               
                             memcpy(ciagDoPodpisu+0, &CtrlResponse,2);
                             memcpy(ciagDoPodpisu+2, &NrRResponse,2);
                             memcpy(ciagDoPodpisu+4, &TNResponse,4);
                             memcpy(ciagDoPodpisu+8, MessResponse, 8 + sizeFile); // 8 + 32 * 43
               
                
              
                         //   std::cout<<"\n\nCiag do wyliczenia podpisu ";          
                         //   for(int m=0; m<1392; m++)
                           //  {
                           //    printf("%02x",   (int)((unsigned char)ciagDoPodpisu[m]) );            
                            //   std::cout<<" ";
                          //   }
          
                              
               
                            char bufferCMac[2024];
                            memset(bufferCMac,0,2024);
                            int sizeCMac = 0;
                            createCMAC(ciagDoPodpisu,this->KeySa,  8 + sizeFile+8 ,16, bufferCMac, &sizeCMac);
             
              
               
               
                           // std::cout<<"\n\nCMAC ";          
                           // for(int m=0; m<sizeCMac; m++)
                           // {
                           //     printf("%02x",   (int)((unsigned char)bufferCMac[m]) );            
                           //     std::cout<<" ";
                          //  }         
               
                       
               
                            memcpy(MessResponse + 8 + sizeFile ,bufferCMac,8); //tylko pierwsze osiem
               
                          //  std::cout<<"\n\nCiag podpisany: ";          
                          //  for(int m=0; m<1392; m++)
                          //  {
                            //  printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
                           //   std::cout<<" ";
                           // }
                        
                              
                            //zaszyfrouj..
               
                            char block[16];
                            memcpy(block, &CtrlResponse,2);
                            memcpy(block+2,&NrRResponse,2);
                            memcpy(block+4,&TNResponse,4);
                            memset(block+8,0,7);
                            memset(block+15,0,1);
                
                
                          //  std::cout<<"\n\nBlok danych dal CTR: ";          
                          //  for(int m=0; m<16; m++)
                              // {
                             //      printf("%02x",   (int)((unsigned char)block[m]) );            
                              //     std::cout<<" ";
                              // }
               
                               char encrypted[2080];
                               //aes128Encrypt(MessResponse, this->KeySa, 88, 16,encrypted, block, 16);
                              aes128Encrypt(MessResponse, this->KeySe, 8 + sizeFile  + 8, 16,encrypted, block, 16);
               
                              memcpy(MessResponse, encrypted, 8 + sizeFile  + 8);
              
                            //  std::cout<<"\n\nCiag podpisany i zaszyfrowany: ";          
                            //  for(int m=0; m<1392; m++)
                              //    {
                               //      printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
                                //     std::cout<<" ";
                                //  }
               
               
               
                                  memcpy(response+0,&CtrlResponse,2);
                                  memcpy(response+2,&NrRResponse,2);
                                  memcpy(response+4,&TNResponse,4);
                                  memcpy(response+8,MessResponse,8 + sizeFile  + 8);
               
                              
                                 unsigned int crc = crc32b(response, sizeResponse-4);
                       
                                 memcpy(response + sizeResponse-4 ,&crc,4);//odpowiedz bez nagówka ramki
               
             
                             //   std::cout<<"\n\nResponse ";          
                              //  for(int m=0; m<1404; m++)
                              //  {
                              //   printf("%02x",   (int)((unsigned char)response[m]) );            
                              //   std::cout<<" ";
                              //  }
                     
               
                                *type = 4; //wyslano w klasie...                
                
                               write(this->socket , response ,sizeResponse  );
                               usleep(1000 * 1000); //5 ms wait for data  
                      
                      
                      
               
               }//koniec innych oboektów..
               
             }
            
            if(this->C[0] == 'R'  ) //odczytanie rejestracji...
            {
         
                char Cack = 0; //potwierdzenie zapisania danych...
                
                
                std::cout<<"\n\n\nOtrzymano rozkaz 'R' - odczytanie rejestracji... ";
             
                
                int iloscDanych = this->MessSize -8 - 8; //-8 nagłowka i - 8 cmac..
                int iloscRejestracji = iloscDanych / 12;
                
                std::cout<<"\nIlosc rejestracji: "<<iloscRejestracji<<"\n";
                
                char* tmpBuf = new char[iloscDanych];
                memcpy(tmpBuf, this->Mess+8,iloscDanych);
                
                if( register_card( this->Install, tmpBuf, iloscDanych)) Cack = 0x06;
                
                delete[] tmpBuf;
                
                
             
                short sizeResponse = 28 ; //ctrl nrr tn ctr ACK = 1 bajt
                char response[sizeResponse];
                 
                
                short CtrlResponse = sizeResponse;    //2 bajty     
                      CtrlResponse |= 0b0100000000000000; //14 szyfrowwniae ramki...
                      CtrlResponse |= 0b0010000000000000; //13 12 10 transjimsia w sesji inicowana przez urzadzeni
                      CtrlResponse |= 0b0000100000000000; //bit 11 nadaje komputer
                                     
                      
                short NrRResponse = this->NrR; //kolejny numer ramki..
                long  TNResponse =  this->TN;
                
                this->NrRamkiK = NrRResponse;
                
                char MessResponse[80]; // 8 nagłowka + 64 danych + 8 na podpis || 64 = 16 sygnatur czyli 16*4=64 bajty
                memcpy(MessResponse+0, this->MessHead,8);
                
             
                memcpy(MessResponse + 1, &Cack,1); //// 0x06
                
                short index = 0; // <<----
                memcpy(MessResponse + 2, &index,2); //zwrocenie odpowiedzi index = 8 pobranie sygnatur kart..
                //memcpy(MessResponse + 3, &index8,1); //zwrocenie odpowiedzi index = 8 pobranie sygnatur kart..
                
                long Syg = 0;
               if( (*this->cardSyg)  != 0 &&  (*this->cardSyg)>0 ) Syg = (*this->cardSyg);   // 
                                        
                memcpy(MessResponse+4, &Syg,4); //sygnatura oboektu
                
                //memset(MessResponse+8,0,16 * 4); //16 sygnatur po 32 bity (4 bajty)             
              
            
                
             //   std::cout<<"\n\nMessResponse bez podpisu: ";          
              //  for(int m=0; m<72; m++)
              //  {
              //    printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
               //  std::cout<<" ";
               // }
                
                char ciagDoPodpisu[80];               
                memcpy(ciagDoPodpisu+0, &CtrlResponse,2);
                memcpy(ciagDoPodpisu+2, &NrRResponse,2);
                memcpy(ciagDoPodpisu+4, &TNResponse,4);
                memcpy(ciagDoPodpisu+8, MessResponse,8); // 8 + 64
               
                
              
              // std::cout<<"\n\nCiag do wyliczenia podpisu ";          
              // for(int m=0; m<80; m++)
              // {
              //   printf("%02x",   (int)((unsigned char)ciagDoPodpisu[m]) );            
              //   std::cout<<" ";
              // }
          
                              
               
               char bufferCMac[1024];
               memset(bufferCMac,0,1024);
               int sizeCMac = 0;
               createCMAC(ciagDoPodpisu,this->KeySa,16,16, bufferCMac, &sizeCMac);
             
              
               
               
            //   std::cout<<"\n\nCMAC ";          
             //  for(int m=0; m<sizeCMac; m++)
             //  {
              //   printf("%02x",   (int)((unsigned char)bufferCMac[m]) );            
              //   std::cout<<" ";
              // }
               
                       
               
               memcpy(MessResponse+8,bufferCMac,8); //tylko pierwsze osiem
               
             //  std::cout<<"\n\nCiag podpisany: ";          
             //  for(int m=0; m<80; m++)
             //  {
             //    printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
              //   std::cout<<" ";
              // }
                        
                              
               //zaszyfrouj..
               
                char block[16];
                memcpy(block, &CtrlResponse,2);
                memcpy(block+2,&NrRResponse,2);
                memcpy(block+4,&TNResponse,4);
                memset(block+8,0,7);
                memset(block+15,0,1);
                
                
              //  std::cout<<"\n\nBlok danych dal CTR: ";          
              // for(int m=0; m<16; m++)
              // {
              //   printf("%02x",   (int)((unsigned char)block[m]) );            
              //   std::cout<<" ";
              // }
               
               char encrypted[80];
               //aes128Encrypt(MessResponse, this->KeySa, 88, 16,encrypted, block, 16);
               aes128Encrypt(MessResponse, this->KeySe, 16, 16,encrypted, block, 16);
               
               memcpy(MessResponse, encrypted,16);
              
            //  std::cout<<"\n\nCiag podpisany i zaszyfrowany: ";          
             //  for(int m=0; m<80; m++)
              // {
              //   printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
              //   std::cout<<" ";
              // }
               
               
               
               memcpy(response+0,&CtrlResponse,2);
               memcpy(response+2,&NrRResponse,2);
               memcpy(response+4,&TNResponse,4);
               memcpy(response+8,MessResponse,16);
               
                              
               unsigned int crc = crc32b(response, 24);
                       
               memcpy(response+24,&crc,4);//odpowiedz bez nagówka ramki
               
             
              // std::cout<<"\n\nResponse ";          
              // for(int m=0; m<92; m++)
             //  {
             //    printf("%02x",   (int)((unsigned char)response[m]) );            
             //    std::cout<<" ";
             //  }
                     
               
                *type = 4; //wyslano w klasie...                
                
                write(this->socket , response ,28  );
                
             
                
                return true;
               
               std::cout<<"\n\n\n";
                
            }
         
            
            if(this->C[0] == 'Y'  ) //przeslanie upgaradu.. w indexcie numer strony, strona ma 528 bajtów.
            {         
                short Index = 0;
                memcpy(&Index, this->MessHead + 2 ,2 );    
                
                
                std::cout<<"\n\n\nOtrzymano rozkaz 'Y' - index: "<<Index;
             
                           
                int begData  = 0;
                int endData  = 0;
                
                
                int Limit =   528;
                begData = Index * Limit;
                
                endData = begData + Limit;
                if(endData > *this->upgadeFileSize) endData = *this->upgadeFileSize;
                
                int sizeData = endData - begData;
                if(sizeData < 0) sizeData = 0;
                
                
              
                short sizeResponse = 8 + 8 + sizeData + 8 + 4 ; //heae messhEAD + DATA + CMAC + CRC32
                char response[sizeResponse];
                 
                
                short CtrlResponse = sizeResponse;    //2 bajty     
                      CtrlResponse |= 0b0100000000000000; //14 szyfrowwniae ramki...
                      CtrlResponse |= 0b0010000000000000; //13 12 10 transjimsia w sesji inicowana przez urzadzeni
                      CtrlResponse |= 0b0000100000000000; //bit 11 nadaje komputer
                                     
                      
                short NrRResponse = this->NrR; //kolejny numer ramki..
                long  TNResponse =  this->TN;
                
                this->NrRamkiK = NrRResponse;
                
                char MessResponse[2000]; // 8 nagłowka + 64 danych + 8 na podpis || 64 = 16 sygnatur czyli 16*4=64 bajty
                memcpy(MessResponse+0, this->MessHead,8);
                
             
                std::cout<<"\n\nSend Upgrade "<< (begData + sizeData) <<" z "<<*this->upgadeFileSize;
                
                memset(MessResponse + 8, 0, sizeData);                                 
                memcpy(MessResponse + 8, this->upgradeBuffer + begData, sizeData);
                
                             
                long Syg = 0; 
                               
                if( *this->upgadeFileSize > 1024) //jakis plik z aktualizacja został załadowany..
                {
                    memcpy(&Syg, this->upgradeBuffer+13,4);                                           
                }                                          
                memcpy(MessResponse+4, &Syg,4); //sygnatura oboektu
                               
            
                
                char ciagDoPodpisu[2000];               
                memcpy(ciagDoPodpisu+0, &CtrlResponse,2);
                memcpy(ciagDoPodpisu+2, &NrRResponse,2);
                memcpy(ciagDoPodpisu+4, &TNResponse,4);
                memcpy(ciagDoPodpisu+8, MessResponse, 8 + sizeData ); // MessHeade + dane upgradu.. BEZ cMAC
               
                
              
              // std::cout<<"\n\nCiag do wyliczenia podpisu ";          
              // for(int m=0; m<80; m++)
              // {
              //   printf("%02x",   (int)((unsigned char)ciagDoPodpisu[m]) );            
              //   std::cout<<" ";
              // }
                                                       
               char bufferCMac[1024];
               memset(bufferCMac,0,1024);
               int sizeCMac = 0;
               createCMAC(ciagDoPodpisu,this->KeySa,8 + 8 + sizeData ,16, bufferCMac, &sizeCMac);
           
               
              //   std::cout<<"\n\nCMAC ";          
              //  for(int m=0; m<sizeCMac; m++)
              //  {
              //   printf("%02x",   (int)((unsigned char)bufferCMac[m]) );            
              //   std::cout<<" ";
              // }
               
                                      
             memcpy(MessResponse+8 + sizeData,bufferCMac,8); //tylko pierwsze osiem
               
             //  std::cout<<"\n\nCiag podpisany: ";          
             //  for(int m=0; m<80; m++)
             //  {
             //    printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
             //   std::cout<<" ";
             // }
                        
                              
            //zaszyfrouj..
               
                char block[16];
                memcpy(block, &CtrlResponse,2);
                memcpy(block+2,&NrRResponse,2);
                memcpy(block+4,&TNResponse,4);
                memset(block+8,0,7);
                memset(block+15,0,1);
                
                
              //  std::cout<<"\n\nBlok danych dal CTR: ";          
              // for(int m=0; m<16; m++)
              // {
              //   printf("%02x",   (int)((unsigned char)block[m]) );            
              //   std::cout<<" ";
              // }
               
               char encrypted[2000];
               //aes128Encrypt(MessResponse, this->KeySa, 88, 16,encrypted, block, 16);
               aes128Encrypt(MessResponse, this->KeySe, 8+8+sizeData, 16,encrypted, block, 16);
               
               memcpy(MessResponse, encrypted,8+8+sizeData);
              
            //  std::cout<<"\n\nCiag podpisany i zaszyfrowany: ";          
             //  for(int m=0; m<80; m++)
              // {
              //   printf("%02x",   (int)((unsigned char)MessResponse[m]) );            
              //   std::cout<<" ";
              // }
               
               
               
               memcpy(response+0,&CtrlResponse,2);
               memcpy(response+2,&NrRResponse,2);
               memcpy(response+4,&TNResponse,4);
               memcpy(response+8,MessResponse,8+8+sizeData);
               
                              
               unsigned int crc = crc32b(response, 8 + 8 + sizeData  + 8 );
                       
               memcpy(response+8 + 8 + sizeData  + 8,&crc,4);//odpowiedz bez nagówka ramki
               
             
              // std::cout<<"\n\nResponse ";          
              // for(int m=0; m<92; m++)
             //  {
             //    printf("%02x",   (int)((unsigned char)response[m]) );            
             //    std::cout<<" ";
             //  }
                     
               
                *type = 4; //wyslano w klasie...                
                
                write(this->socket , response ,8 + 8 + sizeData  + 8 + 4  );
                
             
                
                return true;
               
               std::cout<<"\n\n\n";
                
            }
         
            
           }
          
           
           std::cout<<"\n\n";
           return false;
       }
       
       
      
       
};

//------------------------------------------------------------







void generate_num(char* num, int size)
{
    for(int i=0;i<size; i++)
    {
        num[i] = 'p';
    }
    
}

//------------------------------------------------------------

struct str_num
{
    int socket;
    int index;  
};
 
//------------------------------------------------------------

void connect(char* dataIn, int cIn, char* dataOut, int* cOut, int maxBuf)
{
   *cOut = 1;
   dataOut[0]    ='B';
   
   
      
          
          std::string POST = "";
          POST.append("POST ");
          POST.append("/reader");
          POST.append(" HTTP/1.0\r\n");
          
          POST.append("Host: ");
          POST.append("test.mm.edu.pl");
          POST.append("\r\n");
          
          POST.append("User-Agent: ");
          POST.append("mm web plugin/1.0 Błażej Kita ");
          POST.append("\r\n");
          
          POST.append("Content-Type: ");
          POST.append("application/x-www-form-urlencoded");
          POST.append("\r\n");
          
          POST.append("Content-Length: ");
          POST.append( gxh_IntToString( cIn+6 ) ); // + ramka=
          POST.append("\r\n");
          
          POST.append("\r\n");     
          POST.append("ramka=");
          POST.append(dataIn);
          
          
          std::cout<<"Wysylam dane do serwera: "<<POST.c_str()<<"\n\n";
          
          
          
          std::string URL = "mm.edu.pl" ;
          
          /* first what are we going to send and where are we going to send it? */
          int portno =        80;
          const char *host =        URL.c_str();
          const char *message_fmt = POST.c_str();  // "POST /apikey=%s&command=%s HTTP/1.0\r\n\r\n";

          struct hostent *serverx;
          struct sockaddr_in serv_addr;
          int sockfd, bytes, sent, received, total;
          char message[4096],response_serv[4096];
        

          /* fill in the parameters */      
          memcpy(message, message_fmt, strlen(message_fmt));

          /* create the socket */
         sockfd = socket(AF_INET, SOCK_STREAM, 0);
         if (sockfd < 0)
         {                        
             std::cout<<"error opening socket\n";
             return;
         }

          /* lookup the ip address */
         serverx = gethostbyname(host);
         if (serverx == NULL)
         {     
              close(sockfd);
              std::cout<<"not such host\n";
              return;
         }

         /* fill in the structure */
         memset(&serv_addr,0,sizeof(serv_addr));
         serv_addr.sin_family = AF_INET;
         serv_addr.sin_port = htons(portno);
         memcpy(&serv_addr.sin_addr.s_addr,serverx->h_addr,serverx->h_length);

         /* connect the socket */
         if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
         {
               std::cout<<"error connection\n";
               close(sockfd);
               return;
         }
         
         //--setTimeOut-------------------------
         struct timeval tv;
         fd_set fdset;
         FD_ZERO(&fdset);
         FD_SET(sockfd, &fdset);
         tv.tv_sec = 3;             /* 3 second timeout */
         tv.tv_usec = 0;

         if (select(sockfd + 1, NULL, &fdset, NULL, &tv) == 1)
         {
           int so_error;
           socklen_t len = sizeof so_error;
           getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
         }         
         //-------------------------------------

         /* send the request */
         total = strlen(message);
         sent = 0;
         do 
         {
          bytes = write(sockfd,message+sent,total-sent);
           if (bytes < 0)
           {      
               std::cout<<"ERROR writing message to socket\n";
           }
            if (bytes == 0)
            {
             break;
            }
             sent+=bytes;
         } while (sent < total);
         
         
         //dane walssciy
         write(sockfd,dataIn,cIn);

         
        /* receive the response */
        memset(response_serv,0,sizeof(response_serv));
        total = sizeof(response_serv)-1;
        received = 0;
        do {
           bytes = read(sockfd,response_serv+received,total-received);
           if (bytes < 0)
           {              
               std::cout<<"ERROR reading response from socket\n";
           }
           if (bytes == 0)
              break;
           received+=bytes;
           } while (received < total);

        if (received == total)
        {            
            std::cout<<"ERROR storing complete response from socket\n";
        }

        
        close(sockfd);
        
        
        std::cout<<"Dane odebrane "<<received<<" | "<<response_serv;
        
        int indexStart = -1;
        
        for(int m=4; m<received; m++)
        {
            if(response_serv[m-4] == 13 && response_serv[m-3] == 10 && response_serv[m-2] == 13 && response_serv[m-1] ==10)
            {
                indexStart = m;
                break;
            }
        }
        
        
        if(received < 4)
        { 
            *cOut = 5;
            dataOut[0] = 'E';
            dataOut[1] = 'R';
            dataOut[2] = 'R';
            dataOut[3] = 'O';
            dataOut[4] = 'R';
            return;
        }
        
        if ( !( response_serv[indexStart] == 'O' && response_serv[indexStart+1] == 'K'  && response_serv[indexStart+2] == ':'     ) )
        {
            *cOut = 5;
            dataOut[0] = 'E';
            dataOut[1] = 'R';
            dataOut[2] = 'R';
            dataOut[3] = 'O';
            dataOut[4] = 'R';
            return;
        }
        
        
        indexStart += 3; //OK:XXXXXXXXXX
        
        *cOut = 0;
        
        for(int m=4; m<received; m++)
        {
            if(m>=indexStart)
            {
                if(maxBuf < (*cOut) ) break;
                
                dataOut[ *cOut ] = response_serv[m];
                (*cOut)++;
            }
        }
        
        
     
 

          
   
}



int iloscKlientow =0;



struct threads_info
{
     pthread_t thread;
     bool free;
     unsigned long int startTime; //kiedy został uruchomiony watek... ?
     char close; // 1 tak - 2 nie..
     unsigned long numerInstalacji;
     int socket;
     char ip[100];
};


int maxThread = 100;
threads_info thread_list[100];



//watek klienta
void* runThreadClient(void * param)
{
    
     
    iloscKlientow++;
    
    
    std::cout<<"\n\n -----------------------------------------------\n\n";
    std::cout<<"\n   New client, all: "<<iloscKlientow<<"  \n";
    std::cout<<"\n\n -----------------------------------------------\n\n";
    
    
     str_num* strN = (str_num*)param;
     
     
    
    //--------------
    bool runThread = true;
    
    char readyMsg[2048];    
    char buffer[2000];
    int free = 0;
    int maxBuff = 2000;
    
    short NumerRamki = 1;
    
    memset(buffer,0,2000);   //clear buffer    
            
     
    int new_socket = strN->socket;
    
    
    thread_list[strN->index].socket = strN->socket;
    
    
    unsigned long Install = 0; //numer instalacji powiazany z placowka
    unsigned long TN = 0; //numer urzadzenie produkcyjy..
    
    unsigned long CardSyg =  time(NULL); 
    
    int ilosc_obj_kart = 0;
    unsigned long sygObiektow[300];
    
    for(int p=0; p<255; p++)sygObiektow[p] = 0;
    
    int ilosc_kart = 0;
    str_card karty[32000]; ///max 32 tys kart..
    for(int i=0; i<32000; i++)
    {
        memset(karty[i].card,0,43); //ustaw same 0x00
    }
    
    //tutaj pobierz dane kard ------------------
    
    karty[0].card[0] = 0x01;
    karty[0].card[2] = 0x2;
    karty[0].card[3] = 0x3;
    karty[0].card[42] = 0x43;
        
    // oblicz sygnature kard.
   
    char upgradeFile[1024 * 300]; //300 kb
    int  upgradeSizeFile = 0;
    
     
     
     
     char L1[16];
     char L2[16];
     char L3[16];
     
     char KeySa[16];
     char KeySe[16];
     unsigned long TimeSyg; //czas jest sygnatura sesji..
 
     
     
   
     
    
     
     while(runThread)
     {                             
         
         //rozkaz zakonczenia watku..
         if(   thread_list[strN->index].close == 1)
         {
              close(new_socket);                     
            
              std::cout<<"Socekt close\n";                       
              thread_list[strN->index].free = true;
              thread_list[strN->index].startTime = 0;
              thread_list[strN->index].thread = NULL;
              thread_list[strN->index].close = 0;                            
              thread_list[strN->index].socket = 0;     
              memset(thread_list[strN->index].ip,0,100);
    
              delete[] strN;
     
              iloscKlientow--;
              return NULL;
             
         }
         
         
            thread_list[strN->index].numerInstalacji = Install;
            
             
            //usleep(1000 * 1000); //5 ms wait for data                        
     
            memset(readyMsg,0,2048);   //clear buffer    
            
           
            int count = recv(new_socket, readyMsg, 2048, 0);                        
    
            
            if(count <= 0) 
            {                    
              std::cout<<"\n\n\n\nClient disconnect\n\n\n\n";
                          
              close(new_socket);                     
            
              std::cout<<"Socekt close\n";                       
              thread_list[strN->index].free = true;
              thread_list[strN->index].startTime = 0;
              thread_list[strN->index].thread = NULL;
              thread_list[strN->index].close = 0;     
              thread_list[strN->index].socket = 0; 
              memset(thread_list[strN->index].ip,0,100);
    
              delete[] strN;
     
              iloscKlientow--;
              return NULL;
             
        
                

                return NULL; //zakoncz watek..
            }            
 
       
            
                    
            int diff = maxBuff - free; //ile miejsca pozostalo..
            if(count > diff)
            {
                for(int m=0; m<count; m++) //przesun bity o liczbe przeczytanych..
                {
                  for(int p=0; p<maxBuff-1; p++)
                  {
                    buffer[p] = buffer[p+1];                   
                  }
                }
                
                free -= count;
            }
         
            
            for(int w=0; w<count;w++)
            {                
                buffer[free] = readyMsg[w];
                free++;
            }
   
  
            
            //MMFrame* mmFrame = new MMFrame(buffer,free);      
            MMFrame* mmFrame = new MMFrame(readyMsg,count);      
            
            mmFrame->setUpgradeFileSize(&upgradeSizeFile);
            mmFrame->setUpgaredBuffer(upgradeFile);
            
            mmFrame->setInstall(Install);
            mmFrame->setTypUrzadzeniaTN(TN);
            mmFrame->setCardSyg(&CardSyg); //sygnatur kard..
            mmFrame->setCards(karty);
            mmFrame->setIloscKart(&ilosc_kart);
                        
 
            mmFrame->setIloscObj(&ilosc_obj_kart);
            mmFrame->setSgnaturyObj(sygObiektow);
            
            mmFrame->setSocket(new_socket);
            
            mmFrame->setNumerRamki(NumerRamki);
            
            mmFrame->setL1(L1);
            mmFrame->setL2(L2);
            mmFrame->setL3(L3);
            
            mmFrame->setKeySa(KeySa);
            mmFrame->setKeySe(KeySe);
            mmFrame->setTimeSyg(TimeSyg);
            
            int type = -1;
            int size = 0;
            char bufferFrame[2024];            
            
            bool check = mmFrame->analizeFrame(&type,bufferFrame, &size);                    
            
            if(check == true && type == 1) // odebrano rozkaz nr 1... odpowiadamy 2
            {
                write(new_socket , bufferFrame ,size  ); 
                std::cout<<"\nsend bytes: "<<size<<"\n\n";
                
                mmFrame->getL1(L1);
                mmFrame->getL2(L2); //wylosowalismy liczbe
            }
            
            if(check == true && type == 3) // odebrano rozkaz nr 3
            {
            //    write(new_socket , bufferFrame ,size  ); 
              //  std::cout<<"\nsend bytes: "<<size<<"\n\n";
                
                mmFrame->getL3(L3);
                mmFrame->getKeySa(KeySa);
                mmFrame->getKeySe(KeySe);
                mmFrame->getTimeSyg(&TimeSyg);
                
                std::cout<<"\n\n--- sesja ustawiona -- >> \n";
            }
            
            if(type == 4) //wysłana w klasie..
            {  
                             
                 
                 std::cout<<"\nwyslano w klasie..: "<<"\n\n";
            }
            
            if(type == -1)
            {
                std::cout<<"\nnot sended: "<<size<<"\n\n";
            }
            
            unsigned long InstallNew = mmFrame->getNumInstall(); //pobierz numer instalacji.. moze sie zmienił..
            TN = mmFrame->getTypUrzadzeniaTn();
            
            if(Install == 0 && Install != InstallNew) //nowy numer instalacji inny niz zero
            {
                //zarejestruj numer instalacji...
                register_reader(  InstallNew, thread_list[strN->index].ip , TN);
            }
            
            Install = InstallNew; //pobierz numer instalacji.. moze sie zmienił..
            
            mmFrame->getNumerRamki(&NumerRamki);
            delete mmFrame;
            
           ///-------------------------------------------------------------------------------
           ///-------------------------------------------------------------------------------
      
           //  char response[5000];
           //  memset(response,0,5000);
           //  int cResponse = 0;
       
            // connect(readyGXH,ilosc,response, &cResponse, 5000);
       
            // std::cout<<"\n\nDane od mma: "<<cResponse<<"|"<<response;
             
            // write(new_socket , response ,cResponse  );  
             ///-------------------------------------------------------------------------------  
             ///-------------------------------------------------------------------------------  
      }  
                 
        
    close(new_socket);                     
            
    std::cout<<"Socekt close\n";                       
    thread_list[strN->index].free = true;
    thread_list[strN->index].startTime = 0;
    thread_list[strN->index].thread = NULL;
    thread_list[strN->index].close = 0;
    thread_list[strN->index].socket = 0; 
    memset(thread_list[strN->index].ip,0,100);
            
    
    delete[] strN;
    
    iloscKlientow--;
    return NULL;
};




//głowny wątek serara..
void* runThread(void * param)
{
    //sync attack
    //https://www.symantec.com/connect/articles/hardening-tcpip-stack-syn-attacks
    // netstat -anlp | grep :7777
    
    std::cout<<"start thread listnener\n";
    
    sockaddr_in client;
    int new_socket; 
    int c;      
   
   
    
    while(true)
    {
        std::cout<<"\n\nWaiting for new client\n";
        
        c = sizeof(struct sockaddr_in);
        new_socket = accept(  socket_desc , (struct sockaddr *)&client, (socklen_t*)&c);
        if(new_socket < 0) 
        {
            std::cout<<"Blad klienta\n";
            continue;                                 
        }
        
       char *ip = inet_ntoa(client.sin_addr);
        
        pthread_t threadClient;
        
        
        
        
        //uruchom watek dla klienta..         
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED); //po zakonczeniu zwolni sie od razu pamiec...
       
     
       
        
        int indexFree = -1;
               
      
        for(int k=0; k<maxThread;k++)
        {                              
           if( thread_list[k].free == true)
           {                            
              indexFree = k;
              break;
           }
        };
        
        
        if(indexFree >-1)
        {
            
         str_num* strN = new str_num[1]; // struktora usuwana z pamięci w waku potomnym...
         strN[0].socket = new_socket;
         strN[0].index = indexFree;
        
         int rc = pthread_create(&threadClient, &attr,  &runThreadClient, (void*)strN );
         if (rc)
         {
           std::cout<<"\nUnable to create core thread client!\n";
           pthread_attr_destroy(&attr);
           close(socket_desc);
           continue;
         } else
         {                                                                    
              std::cout<<"\nWatek dodany do tablicy....!\n" ;       
               
              thread_list[indexFree].startTime =time(NULL);
              thread_list[indexFree].thread = runThreadClient;
              thread_list[indexFree].free = false;                                        
              strcpy(thread_list[indexFree].ip, ip  );
         }
         
        }
         
        pthread_attr_destroy(&attr);
        
        
        sleep(5); //odczekaj na polaczenie kolejnego klienta.. max co 5 sek nowe urzadzenie moze sie polaczyc..
    
    }
    
    
    return NULL;
       
};




//------------------------------------------------------------


//------------------------------------------------------------
//------------------------------------------------------------

int main(int argc, char** argv) 
{
  
   
    
    goClose = 0;
    
    std::cout<<"\n"   ;
    std::cout<<"Starting....\n";
    
    
    //buffor wątkuów..
    for(int k=0; k<maxThread;k++)
    {
       thread_list[k].thread = NULL;
       thread_list[k].free = true; 
       thread_list[k].startTime = 0;
       thread_list[k].close = 0;
       thread_list[k].numerInstalacji = 0;       
       thread_list[k].socket = 0;
       memset(thread_list[k].ip,0,100);
       
    };
    
    
    
    std::cout<<"Create socket....\n";        
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
     
    if (socket_desc == -1)
    {
        std::cout<<"Cannot create socket\n";
        return 0 ;
    }
    
    
    int yes=1;     
    if (setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) 
    {
        std::cout<<"Could not save sockopt\n";
        return 0; 
    }
    
    
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    //server.sin_port = htons( 49160 );  //standard
    server.sin_port = htons( 49160 ); 
    
    
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
         {
            std::cout<<"Bind failed\n";
            close(socket_desc);
            return 0;
         }
    
    
    std::cout<<"Start listen\n";
    listen(socket_desc ,  5 );    //maksymalna ilosc klientów...
    
    
    //uruchom głowny wątek serra..
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED); //po zakonczeniu zwolni sie od razu pamiec...
       
     
    std::cout<<"Create thread\n";
    int rc = pthread_create(&thread, &attr,  &runThread, (void*)NULL );
    if (rc)
    {
        std::cout<<"Unable to create core thread!\n";
        pthread_attr_destroy(&attr);
        close(socket_desc);
         return 0 ;
    }
         
    pthread_attr_destroy(&attr);
    
   
    
    while(true)
    {
        if(goClose == 1) break;
     //   std::cout<<"Working...";        
        
       for(int k=0; k<maxThread;k++)
       {      
          sleep(10);
           
           unsigned long int sec= time(NULL);
           unsigned long int diff = sec - thread_list[k].startTime;
           
           unsigned long int maxSec = 60 * 12; //15 min maksmylany czas połączenia....
           unsigned long int maxSec2 = 60 * 13; //15 min maksmylany czas połączenia....
           
           if( thread_list[k].free == false && thread_list[k].startTime != 0 )
           {
               std::cout<<"\033[1;33m"<<"\nWatek nr "<<k<<" IP:"<<thread_list[k].ip<<", Nr instalacji: "<<thread_list[k].numerInstalacji<<", Czas pracy: "<<diff<<" sek."<<"\033[0m\n";
           }
           
           if( thread_list[k].free == false && thread_list[k].startTime != 0  && diff > maxSec && thread_list[k].close != 1)
           {              
              thread_list[k].close = 1; //zamknij watek...              
              if(thread_list[k].socket != 0) shutdown(thread_list[k].socket, SHUT_RDWR );
              std::cout<<"\nZamykam watek klienta wyslano polecenie...!"<<thread_list[k].socket<<"\n" ;           
              continue;
           }
           
           
           //jeśli wątek po wysłaniu polecenie sie nie zamknął to ubij go na siłe
           if( thread_list[k].free == false && thread_list[k].startTime != 0  && diff > maxSec2)
           {              
              if(thread_list[k].close == 1) 
              {
                std::cout<<"\nZamykam watek klienta (kill) "<<" IP:"<<thread_list[k].ip<< "!\n" ;
                pthread_exit(  &thread_list[k].thread ) ; //jeśli się nie zamknął to go dobij....               
                thread_list[k].startTime = 0;
                thread_list[k].thread = NULL;
                thread_list[k].numerInstalacji = 0;
                thread_list[k].free = true;
              }
           }
           
       };
              
    }
    
    std::cout<<"\n\nZakonczenie programu. :)";
    
    return 0;
}

