const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Users = require('../model/userSchema');
const config = require('../config/config');
const nodemailer = require("../config/nodemailer");

router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());


router.post('/signup', (req, res) => {
    hashpass = bcrypt.hashSync(req.body.password, 8);
    Users.findOne({ email: req.body.email }, (err, email) => {
        if (email) return res.status(400).send("User Already Exists");
        else {
            const token = jwt.sign({email}, config.secret);
            Users.create({
                name: req.body.name,
                email: req.body.email,
                password: hashpass,
                confirmationCode: token,
                ph_number: req.body.ph_number || null,
                address: req.body.address || null,
                isActive: true
            }, (err, user) => {
                if (err) throw err;
                res.status(200).send('Successfully Registered and check your email to confirm');
            });
            nodemailer.sendConfirmationEmail(
                req.body.name,
                req.body.email,
                token
            );
        }
    });
});

router.get('/confirm/:confirmationCode', (req, res) => {
    Users.findOne({ confirmationCode: req.params.confirmationCode }, (err, data) => {
        if (err) return res.status(500).send('error while confirming');

        if (!data) return res.send({ auth: false, code: "error in verifying" });
        data.status = "Active";
        data.save((err) => {
            if (err) {
                res.status(500).send({ message: err });
                return;
            }
            else { return res.send({ msg: 'your email is confirmed' }); }
        });
    });
});


router.post('/login', (req, res) => {
    Users.findOne({ email: req.body.email }, (err, data) => {
        if (err) return res.status(500).send('error while login');

        if (!data) return res.render('login',{error:{token: "no user found"} });

        else {
            const validPass = bcrypt.compareSync(req.body.password, data.password);

            if (!validPass) {
                return res.send({ auth: false, token: 'invalid password' });
            }
            else if (data.status != "Active") {
                return res.status(401).send({
                    message: "Pending Account. Please Verify Your Email!",
                });
            }
            else {
                if (data.role !="admin"){
                    return res.render('userdash');
                }else{
                    return res.render('admindash');
                }
            }

            // var token = jwt.sign({id:data._id},config.secret,{expiresIn:3600});
            // res.send({auth:true,token:token});
        }
    });
});

router.post('/forgot', (req,res)=>{
    Users.findOne({ email: req.body.email }, (err, data) => {
        if (!data) return res.status(400).send("No Email Exists");
        else{
            var rtoken = jwt.sign({id:data._id},config.secret,{expiresIn:3600});
            var name = data.name;
            data.resetCode = rtoken;
            data.save((err) => {
            if (err) {
                res.status(500).send({ message: err });
                return;
            }else{
                res.send("check ypur email");
            }
        });
            nodemailer.sendResetEmail(
                name,
                req.body.email,
                rtoken
            );
        }
    });
});

router.get('/reset/:resetCode', (req, res) => {
    Users.findOne({ resetCode: req.params.resetCode }, (err, data) => {
        if (err) return res.status(500).send('error while verifying');

        if (!data) return res.send({ auth: false, code: "error in verifying" });
        else{
            return res.render('reset');
        }
    });
});

router.put('/update/:', (req,res)=>{
    Users.findOne({password:req.params.password}, (err,data)=>{
        newPass= req.body.npass;
        confPass= req.body.cpass;

        if (err) return res.status(500).send('error while updating');
            
        if (!data) return res.send({ auth: false, code: "error in updating" });
        else{
            if(newPass!=confPass) return res.send('pasword miss match');
            data.password=confPass;
            data.save((err) => {
                if (err) {
                    res.status(500).send({ message: err });
                    return;
                }
                else { return res.send({ msg: 'your password updated' }); }
            });
        }
    });
});

router.get('/all', (req, res) => {
    Users.find({}, (err, user) => {
        if (err) throw err;
        res.status(200).send(user);
    });
});

module.exports = router;