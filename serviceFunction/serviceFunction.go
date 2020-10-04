/*
Router ==> (req, resp.writer) ==> Middlewarei(MFA) ==> (modified req) ==> Function(MFA)
                                                                            |
                                                                            |
Return error(ok or not ok) to router <==  Middleware <==  (http packet) <==
                                                |
                                                |
                Send response to client   <=====

Router ==> (req, resp.writer) ==> Middleware ==> retrieve userinfo from req; query pdp for userpw
                                                                    |
                                                                    |
                                                 ok or not ok    <==
*/

package serviceFunction

import (
  "fmt"
  "net/http"
  "net/smtp"
  "log"
  
  pass "github.com/sethvargo/go-password/password"
)

var AuthorizedUsers map[string]string

type ServiceFunction interface {
  ApplyFunction(w http.ResponseWriter, req *http.Request) (bool)
}

type ServiceFunctionName struct {
    name string
    // TODO: dst_pdp string, // indicates where the pdp is located
}

func NewServiceFunction(name string) *ServiceFunctionName {
    return &ServiceFunctionName{name: name}
}

func (sf *ServiceFunctionName) ApplyFunction(fn func(w http.ResponseWriter, req *http.Request) bool,
                                                     w http.ResponseWriter, req *http.Request) bool {
  return fn(w, req)
}

func BasicAuth(w http.ResponseWriter, req *http.Request) bool {
  var username, password string
  form := `<html>
      <body>
      <form action="/" method="post">
      <label for="fname">Username:</label>
      <input type="text" id="username" name="username"><br><br>
      <label for="lname">Password:</label>
      <input type="password" id="password" name="password"><br><br>
      <input type="submit" value="Submit">
      </form>
      </body>
      </html>
      `

  _, err := req.Cookie("Username")
  if err != nil {
    if req.Method =="POST" {
      if err := req.ParseForm(); err != nil {
        fmt.Println("Parsing Error")
        w.WriteHeader(401)
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        fmt.Fprintf(w, form)
        return false
      }

      nmbr_of_postvalues := len(req.PostForm)
      if nmbr_of_postvalues != 2 {
        fmt.Println("Too many Post Form Values")
        w.WriteHeader(401)
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        fmt.Fprintf(w, form)
        return false
      }

      usernamel, exist := req.PostForm["username"]
      username = usernamel[0]
      if !exist || username != "alex" {
        fmt.Println("username not present or wrong")
        w.WriteHeader(401)
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        fmt.Fprintf(w, form)
        return false
      }

      passwordl, exist := req.PostForm["password"]
      password = passwordl[0]
      if !exist || password != "test" {
        fmt.Println("password not present or wrong")
        w.WriteHeader(401)
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        fmt.Fprintf(w, form)
        return false
      }

      cookie := http.Cookie{
        Name: "Username",
        Value: username,
        MaxAge: 10,
        Path: "/",
      }
      http.SetCookie(w, &cookie)
      http.Redirect(w, req, "https://f8ce3eb8-5011-4a3c-a312-6077814dceb8.ul.bw-cloud-instance.org/", 303)
      return true

    } else {
      fmt.Println("only post methods are accepted in this state")
      w.WriteHeader(401)
      w.Header().Set("Content-Type", "text/html; charset=utf-8")
      fmt.Fprintf(w, form)
      return false
    }
  }
  return true
}

func OneTimePassAuth(w http.ResponseWriter, req *http.Request) bool {

  // fmt.Printf("\nOneTimePassAuth:\n%v\n\n", req)
  if AuthorizedUsers == nil {
    AuthorizedUsers = make(map[string]string)
  }
  
  var username, password string
  var err error
  
  userForm := `<html>
      <body>
      <form action="/" method="post">
      <label for="fname">Username:</label>
      <input type="text" id="username" name="username"><br><br>
      <input type="submit" value="Submit">
      </form>
      </body>
      </html>
      `
      
  oneTimePassForm := `<html>
      <body>
      <form action="/" method="post">
      <label for="lname">One Time Password:</label>
      <input type="password" id="password" name="password"><br><br>
      <input type="submit" value="Submit">
      </form>
      </body>
      </html>
      `
  cookie, err := req.Cookie("Username")
  if err != nil {
    if req.Method == "GET" {
      w.WriteHeader(401)
      w.Header().Set("Content-Type", "text/html; charset=utf-8")
      fmt.Fprintf(w, userForm)
      return false
    }
    if req.Method =="POST" {
      if err := req.ParseForm(); err != nil {
        fmt.Println("Parsing Error")
        w.WriteHeader(401)
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        fmt.Fprintf(w, userForm)
        return false
      }

      nmbr_of_postvalues := len(req.PostForm)
      if nmbr_of_postvalues != 1 {
        fmt.Println("Too many Post Form Values")
        w.WriteHeader(401)
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        fmt.Fprintf(w, userForm)
        return false
      }
      
      usernamel, exist := req.PostForm["username"]
      username = usernamel[0]
      if !exist || username != "alex" {
        fmt.Println("username not present or wrong")
        w.WriteHeader(401)
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        fmt.Fprintf(w, userForm)
        return false
      }
      cookie := http.Cookie{
        Name: "Username",
        Value: username,
        MaxAge: 50,
        Path: "/",
      }
      http.SetCookie(w, &cookie)
      
      expectedPassword, err := pass.Generate(20, 8, 8, false, false)
      if err != nil {
        log.Fatal(err)
      }
        
      AuthorizedUsers[username] = expectedPassword
        
      // user we are authorizing as
      from := "wekan@cluster.donntu.edu.ua"

      // use we are sending email to
      to := "miroshkinan@gmail.com"

      // server we are authorized to send email through
      host := "smtp.gmail.com"
       
      // Create the authentication for the SendMail()
      // using PlainText, but other authentication methods are encouraged
      auth := smtp.PlainAuth("", from, "Y2FjUvTfg35V47TB", host)
      
      message := []byte("To: miroshkinan@gmail.com\r\n" +
                        "Subject: OneTimePassword\r\n" +
                        "\r\nPassword: " + expectedPassword + "\r\n")

      if err := smtp.SendMail(host+":587", auth, from, []string{to}, []byte(message)); err != nil {
        log.Fatal(err)
      }
      fmt.Println("Email Sent!")        

      w.WriteHeader(401)
      w.Header().Set("Content-Type", "text/html; charset=utf-8")
      fmt.Fprintf(w, oneTimePassForm)
      http.Redirect(w, req, "https://f8ce3eb8-5011-4a3c-a312-6077814dceb8.ul.bw-cloud-instance.org/", 303)
      return false      
    }
  } else { 
    username = cookie.Value
    
    _, err = req.Cookie("OneTimePass")
    if err != nil {
      if req.Method != "POST" {
        fmt.Println("only post methods are accepted in this state")
        w.WriteHeader(401)
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        fmt.Fprintf(w, oneTimePassForm)
        return false
      }
      if req.Method =="POST" {
        if err := req.ParseForm(); err != nil {
          fmt.Println("Parsing Error")
          w.WriteHeader(401)
          w.Header().Set("Content-Type", "text/html; charset=utf-8")
          fmt.Fprintf(w, oneTimePassForm)
          return false
        }

        nmbr_of_postvalues := len(req.PostForm)
        if nmbr_of_postvalues != 1 {
          fmt.Println("Too many Post Form Values")
          w.WriteHeader(401)
          w.Header().Set("Content-Type", "text/html; charset=utf-8")
          fmt.Fprintf(w, oneTimePassForm)
          return false
        }

        passwordl, exist := req.PostForm["password"]
        password = passwordl[0]
        if !exist || password != AuthorizedUsers[username] {
          fmt.Println("password not present or wrong")
          w.WriteHeader(401)
          w.Header().Set("Content-Type", "text/html; charset=utf-8")
          fmt.Fprintf(w, oneTimePassForm)
          return false
        }

        cookie := http.Cookie{
          Name: "OneTimePass",
          Value: password,
          MaxAge: 10,
          Path: "/",
        }
        http.SetCookie(w, &cookie)
        http.Redirect(w, req, "https://f8ce3eb8-5011-4a3c-a312-6077814dceb8.ul.bw-cloud-instance.org/", 303)
        return true
      }
    }
  }
  return true
}
