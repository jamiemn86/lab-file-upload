const mongoose = require('mongoose');
const Schema = mongoose.Schema;
 
const profilePictureSchema = new Schema(
  {
    name: String,
    path: String,
    originalName: String
  },
  { timestamps: true }
);
 
const Picture = mongoose.model('Picture', profilePictureSchema);
 
module.exports = Picture;