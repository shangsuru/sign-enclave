#pragma once

#include <string>
#include <iostream>
#include <cstring>

// Stores, which command type the user entered
enum Command
{
  START, // used internally
  ERROR, // signifies missing arguments
  SIGN,  // the user wants to sign a message
  VERIFY // the user wants to verify a message signature pair
};

// Struct to save the options the user gave via the command line
struct CommandLineArguments
{
  char *message;         // message to sign or verify
  std::string signature; // signature to verify
  bool reset;            // if a new keypair should be generated or loaded from sealed storage
  Command command;       // command is SIGN or VERIFY
};

// String that is printed to the user, when a parsing error occurs
const std::string usage = "usage: %s [-m message_to_sign] [-p message_to_verify -s signature] [--import-keys] \n";

/**
 * Parses the input from the user given via the command line.
 * @returns struct containing user input
 */
CommandLineArguments getArgs(int nargc, char **nargv);