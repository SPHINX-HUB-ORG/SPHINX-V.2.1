#pragma once

#include <unordered_map>
#include <set>
#include <list>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include "cryptoTools/Common/Defines.h"

namespace osuCrypto
{
    // An error that is thrown when the input isn't of the correct form.
    class CommandLineParserError : public std::exception {  };

    // Command Line Parser class.
    // Expecting the input to be of form 
    //   -key_1 val_1 val_2 -key_2 val_3 val_4 ...
    // The values are optional but require a preceeding key denoted by -
    class CLP
    {
    public:

        // Default Constructor
        CLP() = default;

        // Parse the provided arguments.
        CLP(int argc, char** argv) { parse(argc, argv); }

        // Internal variable denoting the name of the program.
        std::string mProgramName;

        // The key value store of the parsed arguments.
        std::unordered_map<std::string, std::list<std::string>> mKeyValues;

        // parse the command line arguments.
        void parse(int argc, char const*const* argv);

        // Set the default for the provided key. Keys do not include the leading `-`.
        void setDefault(std::string key, std::string value);

        // Set the default for the provided key. Keys do not include the leading `-`.
        void setDefault(std::vector<std::string> keys, std::string value);

        // Set the default for the provided key. Keys do not include the leading `-`.
        void setDefault(std::string key, i64 value) { setDefault(key, std::to_string(value)); }

        // Set the default for the provided key. Keys do not include the leading `-`.
        void setDefault(std::vector<std::string> keys, i64 value) { setDefault(keys, std::to_string(value)); }

        // Manually set a flag.
        void set(std::string name);

        // Return weather the key was provided on the command line or has a default.
        bool isSet(std::string name)const;

        // Return weather the key was provided on the command line or has a default.
        bool isSet(std::vector<std::string> names)const;

        // Return weather the key was provided on the command line has an associated value or has a default.
        bool hasValue(std::string name)const;

        // Return weather the key was provided on the command line has an associated value or has a default.
        bool hasValue(std::vector<std::string> names)const;

        // Return the first value associated with the key.
        template<typename T>
        T get(const std::string& name)const
        {
            if (hasValue(name) == false)
                throw CommandLineParserError();

            std::stringstream ss;
            ss << *mKeyValues.at(name).begin();

            T ret;
            ss >> ret;

            return ret;
        }
        template<typename T>
        T getOr(const std::string& name, T alternative) const
        {
            if (hasValue(name))
                return get<T>(name);

            return alternative;
        }

        template<typename T>
        T getOr(const std::vector<std::string>& name, T alternative)const
        {
            if (hasValue(name))
                return get<T>(name);

            return alternative;
        }


        // Return the first value associated with the key.
        template<typename T>
        T get(const std::vector<std::string>& names, const std::string& failMessage = "")const
        {
            for (auto name : names)
                if (hasValue(name))
                    return get<T>(name);

            if (failMessage != "")
                std::cout << failMessage << std::endl;

            throw CommandLineParserError();
        }

		// Return the values associated with the key.
		template<typename T>
		std::vector<T> getManyOr(const std::string& name, std::vector<T>alt)const
		{
			if (isSet(name))
			{
				auto& vs = mKeyValues.at(name);
				std::vector<T> ret(vs.size());
				auto iter = vs.begin();
				for (u64 i = 0; i < ret.size(); ++i)
				{
					std::stringstream ss(*iter++);
					ss >> ret[i];
				}
				return ret;
			}
			return alt;
		}

        // Return the values associated with the key.
        template<typename T>
        std::vector<T> getMany(const std::string& name)const
        {
			return getManyOr<T>(name, {});
        }



        // Return the values associated with the key.
        template<typename T>
        std::vector<T> getMany(const std::vector<std::string>& names)const
        {
            for (auto name : names)
                if (hasValue(name))
                    return getMany<T>(name);

            return {};
        }


        // Return the values associated with the key.
        template<typename T>
        std::vector<T> getMany(const std::vector<std::string>& names, const std::string& failMessage)const
        {
            for (auto name : names)
                if (hasValue(name))
                    return getMany<T>(name);

            if (failMessage != "")
                std::cout << failMessage << std::endl;

            throw CommandLineParserError();
        }
    };
}
