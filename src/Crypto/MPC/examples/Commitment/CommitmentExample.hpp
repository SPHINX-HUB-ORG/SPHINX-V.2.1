/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2016 LIBSCAPI (http://crypto.biu.ac.il/SCAPI)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* Libscapi uses several open source libraries. Please see these projects for any further licensing issues.
* For more information , See https://github.com/cryptobiu/libscapi/blob/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


#pragma once
#include "../../include/interactive_mid_protocols/CommitmentScheme.hpp"
#include "../../include//interactive_mid_protocols/CommitmentSchemePedersen.hpp"
#include "../../include//interactive_mid_protocols/CommitmentSchemePedersenHash.hpp"
#include "../../include//interactive_mid_protocols/CommitmentSchemePedersenTrapdoor.hpp"
#include "../../include//interactive_mid_protocols/CommitmentSchemeSimpleHash.hpp"
#include "../../include//interactive_mid_protocols/CommitmentSchemeElGamal.hpp"
#include "../../include//interactive_mid_protocols/CommitmentSchemeElGamalHash.hpp"
#include "../../include/interactive_mid_protocols/CommitmentSchemeEquivocal.hpp"

#include <boost/thread/thread.hpp>
#include "../../include/comm/Comm.hpp"
#include "../../include/infra/Scanner.hpp"
#include "../../include/infra/ConfigFile.hpp"

struct CommitmentParams {
	IpAddress committerIp;
	IpAddress receiverIp;
	int committerPort;
	int receiverPort;
	string protocolName;

	CommitmentParams(IpAddress committerIp, IpAddress receiverIp, int committerPort, int receiverPort, string protocolName) {
		this->committerIp = committerIp;
		this->receiverIp = receiverIp;
		this->committerPort = committerPort;
		this->receiverPort = receiverPort;
		this->protocolName = protocolName;
	};
};

