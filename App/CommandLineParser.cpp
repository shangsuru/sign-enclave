#include "CommandLineParser.h"

CommandLineArguments getArgs(int nargc, char **nargv)
{
  CommandLineArguments args = {NULL, "", false, START};

  for (int i = 0; i < nargc; i++)
  {
    // Options
    std::cout << nargv[i] << std::endl;
    if (std::strcmp(nargv[i], "--import-keys") == 0) // import keys for signing and verification from SEALED_DATA_FILE
    {
      args.importKeys = true;
    }
    else
    {
      // Arguments
      if (nargv[i][0] == '-' && i < nargc - 1)
      {
        switch (nargv[i][1])
        {
        case 'm': // message to sign
          if (args.command != START)
            goto error;

          args.message = nargv[++i];
          args.command = SIGN;
          break;
        case 'p': // message to verify
          if (args.command != START && args.command != VERIFY)
            goto error;

          args.message = nargv[++i];
          args.command = VERIFY;
          break;
        case 's': // signature of the message
          if (args.command != START && args.command != VERIFY)
            goto error;

          args.signature.assign(nargv[++i]);
          args.command = VERIFY;
          break;
        default:
          goto error; // Unknown command line option
        }
      }
    }
  }

  if (args.command == START || (args.command == VERIFY && (args.message == NULL || args.signature == "")))
    goto error; // Missing arguments

  return args;

error:
  std::cout << usage << std::endl;
  args.command = ERROR;
  return args;
}