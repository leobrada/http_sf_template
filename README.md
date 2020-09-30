# http_sf
Contains the golang module for the HTTP based service function template

# ToDo
* Client behavior for communication with PEP(API) for feedback/asynchronous messages 

# Structure
* package http_sf 
  * http_sf.go
    * main()
    * init()
  * module: router
    * struct router
      * frontend
      * middleware (the actual function functionality is processed here)
       --> decides if packet is forwarded or returned immediatelly
       --> returns information for the PEP inside of the HTTP header
      * http.NewReverseProxy
  * module: env
