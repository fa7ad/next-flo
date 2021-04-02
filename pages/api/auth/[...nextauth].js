import jwt from "jsonwebtoken";
import NextAuth from "next-auth";
import Providers from "next-auth/providers";

// For more information on each option (and a full list of options) go to
// https://next-auth.js.org/configuration/options
export default NextAuth({
  // https://next-auth.js.org/configuration/providers
  providers: [
    Providers.Facebook({
      clientId: process.env.FACEBOOK_ID,
      clientSecret: process.env.FACEBOOK_SECRET,
    }),
    Providers.Google({
      clientId: process.env.GOOGLE_ID,
      clientSecret: process.env.GOOGLE_SECRET,
    }),
  ],
  secret: process.env.SECRET,

  session: {
    jwt: true,
    maxAge: 7 * 24 * 60 * 60, // 7 days
  },

  jwt: {
    secret: process.env.SECRET,
    // A secret to use for key generation (you should set this explicitly)
    // secret: 'INp8IvdIyeMcoGAgFGoA61DdBglwwSqnXJZkgz8PSnw',
    // Set to true to use encryption (default: false)
    // encryption: true,
    // You can define your own encode/decode functions for signing and encryption
    // if you want to override the default behaviour.
    encode: async ({ secret, token, maxAge }) => {
      const jwtClaims = {
        sub: token.id.toString(),
        name: token.name,
        email: token.email,
        iat: Date.now() / 1e3,
        exp: Math.floor(Date.now() / 1e3) + 7 * 24 * 60 * 60,
        "https://hasura.io/jwt/claims": {
          "x-hasura-allowed-roles": ["user"],
          "x-hasura-default-role": "user",
          "x-hasura-role": "user",
          "x-hasura-user-id": token.id,
        },
      };
      const encodedToken = jwt.sign(jwtClaims, secret, { algorithm: "HS256" });
      return encodedToken;
    },
    decode: async ({ secret, token, maxAge }) => {
      const decodedToken = jwt.verify(token, secret, { algorithms: ["HS256"] });
      return decodedToken;
    },
  },

  pages: {
    // signIn: '/auth/signin',  // Displays signin buttons
    // signOut: '/auth/signout', // Displays form with sign out button
    // error: '/auth/error', // Error code passed in query string as ?error=
    // verifyRequest: '/auth/verify-request', // Used for check email page
    // newUser: null // If set, new users will be directed here on first sign in
  },

  callbacks: {
    // async signIn(user, account, profile) { return true },
    // async redirect(url, baseUrl) { return baseUrl },
    async session(session, token) {
      const encodedToken = jwt.sign(token, process.env.SECRET, {
        algorithm: "HS256",
      });
      session.id = token.id;
      session.token = encodedToken;
      return Promise.resolve(session);
    },
    async jwt(token, user, account, profile, isNewUser) { 
      const isUserSignedIn = !!user;
      
      // FIXME: if new user add to DB
      
      if(isUserSignedIn) {
        token.id = user.id.toString();
      }
      return Promise.resolve(token);
    }
  },

  // Events are useful for logging
  // https://next-auth.js.org/configuration/events
  events: {},

  // Enable debug messages in the console if you are having problems
  debug: false,
});
