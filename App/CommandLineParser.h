#pragma once

#include <string>
#include <iostream>

enum CommandLineStatus
{
  START,
  ERROR,
  SIGN,
  VERIFY
};

struct CommandLineArguments
{
  std::string message;
  std::string signature_file;
  CommandLineStatus status;
};

const std::string usage = "usage: %s [-m message_to_sign] [-p message_to_verify -s signature_file]\n";

CommandLineArguments getArgs(int nargc, char **nargv);