const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        unique: true,
        required: true,
    },
    password: {
        type: String,
        required: true,
    },
});

// function () {} is used here instead of () => {} as function () captures `this` as the User instance
// rather than referencing this file
userSchema.pre("save", function (next) {
    const user = this;
    if (!user.isModified("password")) {
        return next();
    }

    bcrypt.genSalt(10, (err, salt) => {
        if (err) {
            return next(err);
        }

        bcrypt.hash(user.password, salt, (err, hash) => {
            if (err) {
                return next(err);
            }
            user.password = hash;
            next();
        });
    });
});

userSchema.methods.comparePassword = function comparePassword(
    candidatePassword
) {
    return new Promise((resolve, reject) => {
        bcrypt.compare(candidatePassword, this.password, (err, isMatch) => {
            if (err) {
                return reject(err);
            }

            if (!isMatch) {
                return reject(false);
            }
            return resolve(true);
        });
    });
};

mongoose.model("User", userSchema);
