#pragma once

#include <string>
#include <iostream>
#include <cstring>

enum Command
{
  START,
  ERROR,
  SIGN,
  VERIFY
};

struct CommandLineArguments
{
  char *message;
  std::string signature;
  bool importKeys;
  Command command;
};

const std::string usage = "usage: %s [-m message_to_sign] [-p message_to_verify -s signature] [--import-keys] \n";

CommandLineArguments getArgs(int nargc, char **nargv);