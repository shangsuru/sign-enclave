#pragma once

#include <string>
#include <iostream>
#include <cstring>

enum Command
{
  START, // used internally
  ERROR, // signifies missing arguments
  SIGN,  // the user wants to sign a message
  VERIFY // the user wants to verify a message signature pair
};

struct CommandLineArguments
{
  char *message;         // message to sign or verify
  std::string signature; // signature to verify
  bool reset;            // if a new keypair should be generated or loaded from sealed storage
  Command command;       // command is SIGN or VERIFY
};

const std::string usage = "usage: %s [-m message_to_sign] [-p message_to_verify -s signature] [--import-keys] \n";

CommandLineArguments getArgs(int nargc, char **nargv);