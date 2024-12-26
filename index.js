const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')
const cors = require('cors');
const { nanoid } = require('nanoid');
const {mongo,User,Event,Register} = require('./db.js')

app.use(express.json()); 
app.use(express.urlencoded({ extended: true })); 
app.use(cors());
app.use((err, req, res, next) => {
    if (err instanceof SyntaxError) { 
      return res.status(400).json({ error: 'Invalid JSON format' });
    }
    next(err);
  });

const generateId = () => nanoid(4);

app.listen(6969,()=>{console.log("Starting server")});

const authenticate = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
  
    if (!token) {
      return res.status(401).json({ error: 'Access denied. No token provided.' });
    }
  
    try {
      const decoded = jwt.verify(token, process.env.KEY);
      console.log(decoded); 
      req.currUser = decoded;  
      next();
    } catch (error) {
      res.status(400).json({ error: 'Invalid token' });
    }
  };
  
  const rolechecker = (roles = []) => {
    return (req,res,next) => {
      if (!req.currUser) return res.status(401).json({ error: 'Unauthorized. No user context.' });
      if (roles.length && !roles.includes(req.currUser.role))  return res.status(403).json({ error: 'No permission' });
      next();
    }
  }


  //user
  app.post('/auth/users',async(req,res) => {
    try {
      let {sid,name,email,password,department,year} = req.body;
      if (!sid || !name || !email || !password || !department || !year) return res.status(400).json({"Error":"Insufficient Details"});
      const fetch = await User.findOne({sid:sid});
      if (fetch) return res.status(400).json({"error":`Student ID ${sid} already exists.`});
      const hashedPassword = await bcrypt.hash(password, 10);
      password =  hashedPassword;
      const upData = new User({
        sid,
        name,
        email,
        password,
        department,
        year
      });
      await upData.save();
      let show = upData.toObject();
      delete show.password
      res.status(200).json({"Success":"Added user",show});
    }
    catch(e) {
      res.status(500).json({"Error":"Server Error"});
      console.log(e)
    }
  })

  app.post('/auth/login', async (req, res) => {
    try {
      const { sid, password } = req.body;
      if (!sid || !password) {
        return res.status(400).json({ error: 'Student and password are required' });
      }
  
      const user = await User.findOne({ sid: sid });
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      } 
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }
      const token = jwt.sign(
        { sid: user.sid, role: user.role }, 
        process.env.KEY,  
        { expiresIn: '30m' }  
      );
      res.status(200).json({
        message: 'Login successful',
        token,
        user: {
          sid: user.sid,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      });
  
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Server error' });
    }
  });
  
  app.get('/auth/users',authenticate,rolechecker(['admin']),async(req,res) => {
    const rest = await User.find({},'-password');
    if (rest.length == 0) {
      return res.status(400).json({"Error":"Nothing to display"});
    }
    res.status(200).json(rest);
  })
  
  app.delete('/auth/users/:sid',authenticate,rolechecker(['admin']),async (req,res) => {
    try {
      let {sid} = req.params;
      const result = await User.findOneAndDelete({sid:sid});
      if (!result) return res.status(404).json({"error":"no user found"});
      return res.status(200).json({"Success":"Deleted Succesfully"});
    }
    catch (e) {
      console.log(e);
      res.status(500).json({"Error":"server error"});
    }
  });
  
  app.get('/auth/users/:id',authenticate,rolechecker(['admin']),async(req,res) => {
    try {
      let {id} = req.params
      const rest = await User.find({sid:id},'-password -_id');
      if (rest.length == 0) {
        return res.status(404).json({"Error":`No user found with sid ${id}`});
      }
      res.status(200).json(rest);
    }
    catch (e) {
      res.status(400).json({"Error":"Server Error"})
    }
  });
  
  app.put('/auth/users/:sid',authenticate,async(req,res)=>{
    try {
      let {sid} = req.params;
      const upData = req.body;
      if (sid == undefined || Object.keys(upData).length == 0) {
        return res.status(400).json({"Error":"Insufficient Data"});
      }
      delete upData.sid;
      if (sid != req.currUser.sid && req.currUser.role != "admin") {
        return res.status(400).json({"error" : "you can only modify your own details as a user"});
      }
      if (req.currUser.role != "admin") delete upData.role;
      if ("password" in upData) {
        const hashedPassword = await bcrypt.hash(upData["password"], 10); 
        upData["password"] = hashedPassword;
      }
      const rest = await User.updateOne(
        {sid:sid},
        {$set:upData},
        {runValidators : true}
      );
      if (rest.modifiedCount == 0) {
        return res.status(404).json({ "error": "No user found with that ID or no changes made." });
      }
      return res.status(200).json({"Success":"Modified","Modified": await User.findOne({sid:sid},"-password -_id")});
    }
    catch(e) {
      res.status(500).json({"error":"server error"});
      console.log(e);
    }
  });

//register

app.post("/event/create",authenticate,rolechecker(['admin']), async(req,res) => {
    try {
        const {title,time,description,date,venue,capacity,organiser,tags} = req.body;
        if (!title || !description || !date || !venue || !capacity || !organiser || !tags) return res.status(400).json({"error":"Insufficient Details"});
        const eid = generateId();
        const upData = new Event({
            eid,
            title,
            description,
            date,
            venue,
            capacity,
            organiser,
            tags
        });
        await upData.save();
        res.status(200).json({"success":"Added Event",upData});
    }
    catch(e) {
        console.log(e);
        res.status(500).json({"error":"Server Error"});
    }
});

//get

app.get("/event", authenticate, rolechecker(['admin','user']), async (req, res) => {
    try {
        const events = await Event.find();
        res.status(200).json(events);
    } catch (e) {
        console.log(e);
        res.status(500).json({ "error": "Server Error" });
    }
});

app.get("/event/:eid", authenticate, rolechecker(['admin', 'user']), async (req, res) => {
    try {
        const { eid } = req.params;
        const event = await Event.findOne({ eid });

        if (!event) {
            return res.status(404).json({ "error": "Event Not Found" });
        }

        res.status(200).json(event);
    } catch (e) {
        console.log(e);
        res.status(500).json({ "error": "Server Error" });
    }
});

//put

app.put("/event/:eid", authenticate, rolechecker(['admin']), async (req, res) => {
    try {
        const { eid } = req.params;
        const { title, time, description, date, venue, capacity, organiser, tags } = req.body;

        if (!title || !description || !date || !venue || !capacity || !organiser || !tags) {
            return res.status(400).json({ "error": "Insufficient Details" });
        }

        const updatedEvent = await Event.findOneAndUpdate(
            { equalsid },
            { title, time, description, date, venue, capacity, organiser, tags },
            { new: true } // Returns the updated documen
        );

        if (!updatedEvent) {
            return res.status(404).json({ "error": "Event Not Found" });
        }

        res.status(200).json({ "success": "Updated Event", updatedEvent });
    } catch (e) {
        console.log(e);
        res.status(500).json({ "error": "Server Error" });
    }
});

//delete

app.delete("/event/:eid", authenticate, rolechecker(['admin']), async (req, res) => {
    try {
        const { eid } = req.params;

        const deletedEvent = await Event.findOneAndDelete({ eid });

        if (!deletedEvent) {
            return res.status(404).json({ "error": "Event Not Found" });
        }

        res.status(200).json({ "success": "Deleted Event", deletedEvent });
    } catch (e) {
        console.log(e);
        res.status(500).json({ "error": "Server Error" });
    }
});

//register

app.post("/event/register/:eid",authenticate,async(req,res) => {
    try {
        const {eid} = req.params;
        const event = await Event.findOne({eid});
        if (!event) return res.status(404).json({"error":"event not found"});
        if (event.registered >= event.capacity) return res.status(401).json({"error":"event is full"});
        await Event.updateOne({ eid }, { $inc: { registered: 1 } });
        const check = await Register.findOne({eid,sid : req.currUser.sid});
        if (check) return res.status(401).json({"error":"you have already registered for this event"})
        const upData = new Register({
            rid : generateId(),
            eid ,
            sid : req.currUser.sid,
            name : req.currUser.name,
            department : req.currUser.department,
            year: req.currUser.year
        })
        await upData.save()
        res.status(200).json({"Success":"Succesfully registered for the event","Data" : upData})
    }
    catch (e) {
        res.status(500).json({"error":"server error"});
        console.log(e)
    }
});

app.delete("/event/register/:rid",authenticate,rolechecker(["admin"]),async (req,res) => {
    try {
      const {rid} = req.params;
      const event = await Register.findOne({rid,sid:req.currUser.sid});
      if (!event) return res.status(404).json({"error":"registration not found"});
      await Register.deleteOne({rid});
      
      res.status(200).json({"success":`registration with RID ${rid} deleted succesfully`});
    }
    catch (e) {
      res.status(500).json({"error":"server error"});
      console.log(e)
  }
});

app.post("/event/feedback/:eid",authenticate,async (req,res) => {
    try {
      const {eid} = req.params;
      const event = await Register.findOne({eid,sid:req.currUser.sid});
      const {feedback} = req.body;
      if (!feedback) return res.status(404).send("Empty response not allowed...");
      if (!event) return res.status(404).send("You have not registered for this event");
      await Register.updateOne({eid,sid:req.currUser.sid},{$set : {feedback}});
      res.status(200).send("Feedback submitted...");
    }
    catch (e) {
      res.status(500).json({"error":"server error"});
      console.log(e);
    }
})







