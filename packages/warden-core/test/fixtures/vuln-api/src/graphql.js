const { ApolloServer } = require("@apollo/server");
const typeDefs = require("./schema");
const resolvers = require("./resolvers");

// API-6: no depth/complexity limit → a single nested query can DoS the server.
const server = new ApolloServer({ typeDefs, resolvers });

module.exports = server;
