const express=require('express');
const router=express.Router();

//mongodb user model
const User=require('./../models/User');

//mongodb user Verificattion model
const UserVerification=require('./../models/UserVerification');

//email handler
const nodemailer=require("nodemailer");

//unique String
const {v4: uuidv4}=require("uuid");

//env vaiable
require("dotenv").config();

//password handle
const bcrypt=require('bcrypt');

//path for static verified path
const path=require("path");

//nodemailer stuff
let transporter=nodemailer.createTransport({
    service:"gmail",
    auth:{
        user:process.env.AUTH_EMAIL,
        pass:process.env.AUTH_PASS,
    }
})

//testing success
transporter.verify((error,success)=>{
    if(error){
        console.log(error);
    }else{
        console.log("Ready for messages");
        console.log(success);
    }
})

router.post('/signup',(req,res)=>{
    let{name,email,password}=req.body;
    name=name.trim();
    email=email.trim();
    password=password.trim();

    if(name=="" || email=="" || password==""){
        res.json({
            status:"FAILED",
            message:"Empty input filed"
        });
    }else if(!/^[a-zA-Z ]*$/.test(name)){
        res.json({
            status:"FAILED",
            message:"Invalid name!"
        })
    }else if(!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)){
        res.json({
            status:"FAILED",
            message:"Invalid email!"
        })
    }else if(password.length<8){
        res.json({
            status:"FAILED",
            message:"Invalid password!"
        })
    }else{
        User.find({email}).then(result=>{
            if(result.length){
                res.json({
                    status:"FAILED",
                    message:"User with provived email already exist!"
                })
            }else{
                //creating new user

                //password
                const saltrounds=10;
                bcrypt.hash(password,saltrounds).then(hashedPassword=>{
                    const newUser=new User({
                        name,
                        email,
                        password:hashedPassword,
                        verified:false,
                    });
                    newUser.save().then(result=>{
                        //handle acc verification
                        sendVerificationEmail(result,res);
                    })
                    .catch(err=>{
                        res.json({
                            status:"FAILED",
                            message:"Error occured while saving user account"
                        })
                    })
                }).catch(err=>{
                    res.json({
                        status:"FAILED",
                        message:"Error occured while hashing password!"
                    })
                })
            }
        }).catch(err=>{
            console.log(err);
            res.json({
                status:"FAILED",
                message:"Error occured while checking for existing user"
            })
        })
    }
})

//send verification mail
const sendVerificationEmail=({_id,email},res)=>{
    //url to be used in mail
    const currentUrl="http://localhost:3000/";
    const uniqueString=uuidv4()+_id;

    //mail options
    const mailOptions={
        from:process.env.AUTH_EMAIL,
        to:email,
        subject:"Verify your email",
        html:`<p>Verify your email address to complete signup and login into your account.</p><p>This link <b>expires in 6 hrs</b>.</p><p>Press <a href=${currentUrl+"user/verify/"+_id +"/"+uniqueString}>here</a> to proceed.</p>`,
    };

    //hash the unique string
    const saltRounds=10;
    bcrypt
    .hash(uniqueString,saltRounds)
    .then((hashedUniqueString)=>{
        //set values in user verification collection
        const newVerification=new UserVerification({
            userId:_id,
            uniqueString:hashedUniqueString,
            createdAt:Date.now(),
            expiresAt:Date.now()+21600000,
        });

        newVerification
            .save()
            .then(()=>{
                transporter
                .sendMail(mailOptions)
                .then(()=>{
                    res.json({
                        status:"PENDING",
                        message:"Verification email sent!"
                    });
                })
                .catch((error)=>{
                    console.log(error);
                    res.json({
                        status:"FAILED",
                        message:"Verification email failed!"
                    });
                })
            })
            .catch((error)=>{
                console.log(error);
                res.json({
                    status:"FAILED",
                    message:"couldn't save email verification data!"
                });
            })
    })
    .catch(()=>{
        res.json({
            status:"FAILED",
            message:"An error occured while hashing email data!"
        })
    })
}

//verify email
router.get("/verify/:userId/uniqueString",(req,res)=>{
    let{userId,uniqueString}=req.params;
    UserVerification
    .find({userId})
    .then((result)=>{
        if(result.length>0){
            //user rec verification exists

            const {expiresAt}=result[0];
            const hashedUniqueString=result[0].uniqueString;

            if(expiresAt<Date.now()){
                UserVerification
                .deleteOne({userId})
                .then(result=>{
                    User
                    .deleteOne({_id:userId})
                    .then(()=>{
                        let message="Link has expired.Please signup again";
                        res.redirect(`/user/verified/error=true&messages=${message}`);
                    })
                    .catch(error=>{
                        let message="Clearing user with expired unique string failed";
                        res.redirect(`/user/verified/error=true&messages=${message}`);
                    })
                })
                .catch((error)=>{
                    console.log(error);
                    let message="An error occured while clearing expired user verification record";
                    res.redirect(`/user/verified/error=true&messages=${message}`);
                })
            }else{
                //valid record exists so we validate the user
                //compare hashed unique string
                bcrypt
                .compare(uniqueString,hashedUniqueString)
                .then(result=>{
                    if(result){
                        //strings match
                        User
                        .updateOne({_id:userId},{verified:true})
                        .then(()=>{
                            UserVerification
                            .deleteOne({userId})
                            .then(()=>{
                                res.sendFile(path.join(__dirname,"./../views/verified.html"));
                            })
                            .catch(error=>{
                                console.log(error);
                                let message="An error occured while finalizing successfull verification!";
                                res.redirect(`/user/verified/error=true&messages=${message}`);
                            })
                        })
                        .catch(error=>{
                            console.log(error);
                            let message="An error occured while updating user record to show verified";
                            res.redirect(`/user/verified/error=true&messages=${message}`);
                        })

                    }else{
                        //existing rec but incorrect verification details passed
                        let message="Invalid verification details passed.Check your inbox";
                        res.redirect(`/user/verified/error=true&messages=${message}`);
                    }
                })
                .catch(error=>{
                    let message="An error occured while comparing unique string";
                    res.redirect(`/user/verified/error=true&messages=${message}`);
                })
            }
        }
        else{
            let message="Acc record doesn't exist or verified already. Please signnin";
            res.redirect(`/user/verified/error=true&messages=${message}`);
        }
    })
    .catch((error)=>{
        console.log(error);
        let message="An error occured while checking for existing user verification record";
        res.redirect(`/user/verified/error=true&messages=${message}`);
    })
});

//verified page route
router.get("/verified",(req,res)=>{
    res.sendFile(path.join(__dirname,"./../views/verified.html"));
})

//Signin
router.post('/signin',(req,res)=>{
    let{email,password}=req.body;


    if(email=="" || password==""){
        res.json({
            status:"FAILED",
            message:"Empty crendentials given"
        })
    }else{
        User.find({email})
        .then(data=>{
            if(data.length){
            //user exist
                //check if user is verified

                if(!data[0].verified){
                    res.json({
                        status:"FAILED",
                        message:"Email hasn't been verified yet.Check yout inbox!",
                    });
                }else{
                    const hashedPassword=data[0].password;
                bcrypt.compare(password,hashedPassword).then(result=>{
                    if(result){
                        res.json({
                            status:"SUCCESS",
                            message:"Signin successfull!",
                            data:data
                        })
                    }else{
                        res.json({
                            status:"Failed",
                            message:"Invalid password!"
                        })
                    }
                })
                .catch(err=>{
                    res.json({
                        status:"Failed",
                        message:"Error occured in validating password!"
                    })
                })
                }
            }else{
                res.json({
                    status:"Failed",
                    message:"Invalid Credentials!"
                })
            }
        })
        .catch(err=>{
            res.json({
                status:"Failed",
                message:"An error while checking for existing user"
            })
        })
    }
})

module.exports=router;