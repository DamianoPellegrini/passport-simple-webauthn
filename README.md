# passport-simple-webauthn

This library makes it easier to implement webauthn authentication thanks to [passport](https://github.com/jaredhanson/passport) and [SimpleWebAuthN](https://github.com/MasterKale/SimpleWebAuthn).

It manages the verification part of [SimpleWebAuthN](https://github.com/MasterKale/SimpleWebAuthn), understanding how it works is needed.

### List of content

- [Installation](#installation)
- [Usage](#usage)
- [Recipes](#recipes)

## Installation

```sh
# npm
npm install passport-simple-webauthn @simplewebauthn/server
npm install -D @simplewebauthn/typescript-types

# yarn
yarn add passport-simple-webauthn @simplewebauthn/server
yarn add -D @simplewebauthn/typescript-types

# pnpm
pnpm add passport-simple-webauthn @simplewebauthn/server
pnpm add -D @simplewebauthn/typescript-types
```

## Usage

### Setup strategy

```js
import WebauthnStrategy from 'passport-simple-webauthn';

passport.use(
  new WebauthnStrategy(
    {
      expectedRPID: 'example.com',
      expectedOrigin: 'https://example.com',
      extractor: (req) => req.session.webauthn,
      requireUserVerification: true,
    },
    async (req, credentialId, userHandle) => {
      const user = await User.findOne({ where: { id: userHandle } });

      if (!user) {
        throw new Error('User not found');
      }

      const authenticator = await Authenticator.findOne({
        where: { credentialId, user: user.id },
      });

      return {
        user,
        authenticator,
      };
    },
    async (req, user, registrationInfo, conclude) => {
      try {
        const newUser = await User.create(user, registrationInfo);

        if (!newUser) {
          conclude(new Error("Couldn't register user"));
        }

        conclude(null, newUser);
      } catch (err) {
        conclude(err);
      }
    },
  ),
);
```

> Note: you can use `conclude` callback function or an `async` function or normal function with a `return` statement to return the data

### Authenticate Requests

```js
app.get('/profile', passport.authenticate('webauthn'), function (req, res) {
  res.json(req.user);
});
```

## Recipes

- [NestJS](./recipes/NestJs.md)
