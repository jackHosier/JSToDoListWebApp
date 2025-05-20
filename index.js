/*
Author: Jack Hosier
Date: 11/06/2023
Description: DoToList web application with security 
*/

//all the libraries I need for this 
import express from "express"
import sqlite3  from "sqlite3"
import {open} from "sqlite"
import {engine} from "express-handlebars"
import cookieParser from "cookie-parser"
import bcrypt from 'bcrypt'
import {v4 as uuidv4} from 'uuid'

const port = 8080 //the default port for the website 
const app = express()

const saltRounds = 10 //this is for the bcrypt hash-function 

//connect to database with a promise 
const dbPromise = open({
    filename: "./Database/todolist.sqlite", 
    driver: sqlite3.Database
})

//SET UP APP
app.use(express.static("static")) //find MAIN.CSS for styling 
app.use(express.urlencoded({extended: false}))
app.use(cookieParser()) //set up the cookie parser 

//hook up handlebars 
app.engine('handlebars', engine())
app.set('view engine', 'handlebars')
app.set('views' , "./views")

/*
//-------------------------------------------------\\
 A U T H E N T I C A T I O N     M I D D L E W A R E 
*/

//this authenticates users who are already logged in
const authenticateMiddleware = async (req, res, next) => {

    console.log(req.cookies) //print out the cookies to terminal

    //if no cookies exist, skip ahead
    if(!req.cookies || ! req.cookies.authToken){

        console.log("ERROR: Cookie does not exist")
        return next()
    }

    const db = await dbPromise //connect to DB 
    
    try{ //look up the token in the authTokens table
        console.log('looking up token')
        const token = await db.get('SELECT * FROM authtokens WHERE token = ?', req.cookies.authToken)

        if(token){ //if the token exists, get the user 
            const user = await db.get("SELECT user_id, username FROM users WHERE user_id = ?", token.user_id)
            req.user = user; 
        }

        next(); 
    } catch(err){

        console.log("ERROR: BAD TOKEN ", err)
        return next()
    }
    
}

app.use(authenticateMiddleware)

/*
//-------------------------------------------------\\
                R U N    T H E   A P P
*/

//redirect to home.handlebars
app.get("/", async (req, res) => {
    
    //load the user's task list 
    try{

        const db = await dbPromise //connect to DB

        const user = req.user

        //get the userID cookie 
        let userID = user.user_id

        //get all the user's tasks
        let get_all_tasks_query = 'SELECT tasks.task_id, tasks.task_desc, tasks.is_complete FROM tasks WHERE tasks.user_id = ?;'
        const tasks = await db.all(get_all_tasks_query, userID)
        
        //print the results
        res.render("home", {user, tasks, layout:"main", 
            "task_id": tasks.task_id, 
            "task_desc": tasks.task_desc,
            "is_complete": tasks.is_complete
        })


    } catch(err){
        console.log("an error occured in / get handler: ", err)
    }

})
//check that the server works
app.listen(port, (err) => {
    if(err){
        console.log("an error occured: ", err)
    } else {
        console.log("listening on port " + port)
    }
   
})

/*
//-------------------------------------------------\\
                P A G E    L O A D E R S
*/

//get handler for login.handlebars
app.get("/login", (req, res) =>{

    if(req.user){ //if user already logged in, just go directly to the home page 
        res.redirect('/')
        return
    }
    
    res.render("login") //go to login.handlebars

   
})

//get handler for register.handlebars
app.get("/register", (req, res) =>{

    if(req.user){ //if user already exists, just go directly to the home page 
        res.redirect('/')
        return
    }

    res.render("register") //go to register.handlebars

   
})

//this logs out the user when they end their session
app.get("/logout", async (req, res) => {
    //remove them from the authToken table 

    const db = await dbPromise 

    let removeQuery = "REMOVE FROM authtokens WHERE token = ?"
    let token = req.cookies.authToken

    let result;

    try{

        result = await db.run(removeQuery, token)
    } catch(err){
        
    }

    res.clearCookie("authToken") //clear the cookie 

    res.redirect("/login") //go to the login page 
})


/*
//-------------------------------------------------\\
               P O S T   R E Q U E S T S 
*/

//POST request handler for username on login page
app.post("/login", async (req, res) => {

    const db = await dbPromise //wait for db to connect

    let userName = req.body.username //get the username from the username box 
    let password = req.body.password //get the password from the password box

    try{

        //get the user from the users table
        const user = await db.get("SELECT * FROM users WHERE username = ?;", userName)

        if(!user){ //if the user does not exist 
            return res.render('login', {error: "ERROR: username or password is incorrect"}) //if user not found, reload login page
        } 
        
        //check if the password entered matches the one on file 
        const passwordMatch = await bcrypt.compare(password, user.password)

        if(!passwordMatch){ //if password doesn't match, reload login page 
            return res.render('login', {error: "ERROR: username or password is incorrect"})
        } 
        //create a token for the user cookie
        const token = uuidv4()

        //add the token to the authToken table 
        await db.run("INSERT INTO authtokens (token, user_id) VALUES (?, ?);", token, user.user_id)

        //bake a cookie for the user
        res.cookie("authToken", token)

        res.redirect('/') //go back to the home page
      
    } catch(err){

        console.log("an error occured in app.post('/.login'): ", err)
        
    }

})


//post request for adding a task {REMOVE THIS}
app.post("/add_task", async (req, res) => {

    const db = await dbPromise //connect to DB

    let task = req.body.task //get the task from the text-box

    let userID = req.user.user_id//get the user_id from the cookie

    //add it to the tasks database
    let insertQuery = "INSERT INTO tasks(user_id, task_desc, is_complete) values (?, ?, ?)"
    let values = [userID, task, false]

    await db.get(insertQuery, values, (err) => {

        if(err){
            res.send("an error occured: ", err)
        } else {
            console.log("task added successfully")
        }
    }) 

    res.redirect('/') //redirect to the home page 
})

//post request for registering new users 
app.post("/register", async (req, res) => {

    const db = await dbPromise  

    //get the username from the textbox
    let userName = req.body.username
    let password = req.body.password

    let passwordTwo = req.body.confirmPassword

      //check if the user filled out all the fields
    if(!userName || !password || !passwordTwo || 
        userName.length === 0 || password.length === 0
        || passwordTwo.length === 0){
        return res.render('register', {error: "Fill out all fields to continue registering"})
    }

    //check if both passwords match; if they don't, do this
    if(password !== passwordTwo){

        return res.render("register", {error: "ERROR: ConfirmPassword does not match Password"})
    } 

    //encrypt the password using hash function 
    const hashedPassword = await bcrypt.hash(password, saltRounds)

    let query = `SELECT users.username FROM users WHERE users.username = "${userName}";`
    
    let result
    try{

        result = await db.get(query) //look up the username in the users table to see if it already exists 

        if(result){
            //if username already exists, reload register page with error message
            return res.render("register", {error: "That user already exists"}) 
        } 
        //try adding it to the DB
        try{
            let insertQuery = "INSERT INTO users(username, password) VALUES (?, ?)"
            let values = [userName, hashedPassword]

            await db.run(insertQuery, values)

        } catch(err){
            //if something went wrong 
            res.render("register", {error: `Something went wrong adding the new user: ${err}`})
        }
        
    } catch(err){
        console.log("An error occured while checking if the user already exists: ", err)
    }

    res.redirect("/login") //redirect to the login page 

    

    
})



