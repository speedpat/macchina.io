//
// UnitsOfMeasureServiceSkeleton.cpp
//
// Library: IoT/UnitsOfMeasure
// Package: Generated
// Module:  UnitsOfMeasureServiceSkeleton
//
// This file has been generated.
// Warning: All changes to this will be lost when the file is re-generated.
//
// Copyright (c) 2018-2020, Applied Informatics Software Engineering GmbH.
// All rights reserved.
// 
// SPDX-License-Identifier: GPL-3.0-only
//


#include "IoT/UnitsOfMeasure/UnitsOfMeasureServiceSkeleton.h"
#include "IoT/UnitsOfMeasure/CanonicalValueDeserializer.h"
#include "IoT/UnitsOfMeasure/CanonicalValueSerializer.h"
#include "IoT/UnitsOfMeasure/PrefixDeserializer.h"
#include "IoT/UnitsOfMeasure/PrefixSerializer.h"
#include "IoT/UnitsOfMeasure/PrefixedUnitDeserializer.h"
#include "IoT/UnitsOfMeasure/PrefixedUnitSerializer.h"
#include "IoT/UnitsOfMeasure/UnitDeserializer.h"
#include "IoT/UnitsOfMeasure/UnitSerializer.h"
#include "Poco/RemotingNG/Deserializer.h"
#include "Poco/RemotingNG/MethodHandler.h"
#include "Poco/RemotingNG/RemotingException.h"
#include "Poco/RemotingNG/Serializer.h"
#include "Poco/RemotingNG/ServerTransport.h"
#include "Poco/RemotingNG/TypeDeserializer.h"
#include "Poco/RemotingNG/TypeSerializer.h"
#include "Poco/SharedPtr.h"


namespace IoT {
namespace UnitsOfMeasure {


class UnitsOfMeasureServiceCanonicalizeMethodHandler: public Poco::RemotingNG::MethodHandler
{
public:
	void invoke(Poco::RemotingNG::ServerTransport& remoting__trans, Poco::RemotingNG::Deserializer& remoting__deser, Poco::RemotingNG::RemoteObject::Ptr remoting__pRemoteObject)
	{
		using namespace std::string_literals;
		
		static const std::string REMOTING__NAMES[] = {"canonicalize"s,"value"s,"prefixedCode"s};
		bool remoting__requestSucceeded = false;
		try
		{
			double value;
			std::string prefixedCode;
			remoting__deser.deserializeMessageBegin(REMOTING__NAMES[0], Poco::RemotingNG::SerializerBase::MESSAGE_REQUEST);
			Poco::RemotingNG::TypeDeserializer<double >::deserialize(REMOTING__NAMES[1], true, remoting__deser, value);
			Poco::RemotingNG::TypeDeserializer<std::string >::deserialize(REMOTING__NAMES[2], true, remoting__deser, prefixedCode);
			remoting__deser.deserializeMessageEnd(REMOTING__NAMES[0], Poco::RemotingNG::SerializerBase::MESSAGE_REQUEST);
			IoT::UnitsOfMeasure::UnitsOfMeasureServiceRemoteObject* remoting__pCastedRO = static_cast<IoT::UnitsOfMeasure::UnitsOfMeasureServiceRemoteObject*>(remoting__pRemoteObject.get());
			IoT::UnitsOfMeasure::CanonicalValue remoting__return = remoting__pCastedRO->canonicalize(value, prefixedCode);
			remoting__requestSucceeded = true;
			Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_REPLY);
			static const std::string REMOTING__REPLY_NAME("canonicalizeReply");
			remoting__ser.serializeMessageBegin(REMOTING__REPLY_NAME, Poco::RemotingNG::SerializerBase::MESSAGE_REPLY);
			Poco::RemotingNG::TypeSerializer<IoT::UnitsOfMeasure::CanonicalValue >::serialize(Poco::RemotingNG::SerializerBase::RETURN_PARAM, remoting__return, remoting__ser);
			remoting__ser.serializeMessageEnd(REMOTING__REPLY_NAME, Poco::RemotingNG::SerializerBase::MESSAGE_REPLY);
		}
		catch (Poco::Exception& e)
		{
			if (!remoting__requestSucceeded)
			{
				Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_FAULT);
				remoting__ser.serializeFaultMessage(REMOTING__NAMES[0], e);
			}
		}
		catch (std::exception& e)
		{
			if (!remoting__requestSucceeded)
			{
				Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_FAULT);
				Poco::Exception exc(e.what());
				remoting__ser.serializeFaultMessage(REMOTING__NAMES[0], exc);
			}
		}
		catch (...)
		{
			if (!remoting__requestSucceeded)
			{
				Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_FAULT);
				Poco::Exception exc("Unknown Exception");
				remoting__ser.serializeFaultMessage(REMOTING__NAMES[0], exc);
			}
		}
	}

};


class UnitsOfMeasureServiceConvertMethodHandler: public Poco::RemotingNG::MethodHandler
{
public:
	void invoke(Poco::RemotingNG::ServerTransport& remoting__trans, Poco::RemotingNG::Deserializer& remoting__deser, Poco::RemotingNG::RemoteObject::Ptr remoting__pRemoteObject)
	{
		using namespace std::string_literals;
		
		static const std::string REMOTING__NAMES[] = {"convert"s,"value"s,"fromPrefixedCode"s,"toPrefixedCode"s};
		bool remoting__requestSucceeded = false;
		try
		{
			double value;
			std::string fromPrefixedCode;
			std::string toPrefixedCode;
			remoting__deser.deserializeMessageBegin(REMOTING__NAMES[0], Poco::RemotingNG::SerializerBase::MESSAGE_REQUEST);
			Poco::RemotingNG::TypeDeserializer<double >::deserialize(REMOTING__NAMES[1], true, remoting__deser, value);
			Poco::RemotingNG::TypeDeserializer<std::string >::deserialize(REMOTING__NAMES[2], true, remoting__deser, fromPrefixedCode);
			Poco::RemotingNG::TypeDeserializer<std::string >::deserialize(REMOTING__NAMES[3], true, remoting__deser, toPrefixedCode);
			remoting__deser.deserializeMessageEnd(REMOTING__NAMES[0], Poco::RemotingNG::SerializerBase::MESSAGE_REQUEST);
			IoT::UnitsOfMeasure::UnitsOfMeasureServiceRemoteObject* remoting__pCastedRO = static_cast<IoT::UnitsOfMeasure::UnitsOfMeasureServiceRemoteObject*>(remoting__pRemoteObject.get());
			double remoting__return = remoting__pCastedRO->convert(value, fromPrefixedCode, toPrefixedCode);
			remoting__requestSucceeded = true;
			Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_REPLY);
			static const std::string REMOTING__REPLY_NAME("convertReply");
			remoting__ser.serializeMessageBegin(REMOTING__REPLY_NAME, Poco::RemotingNG::SerializerBase::MESSAGE_REPLY);
			Poco::RemotingNG::TypeSerializer<double >::serialize(Poco::RemotingNG::SerializerBase::RETURN_PARAM, remoting__return, remoting__ser);
			remoting__ser.serializeMessageEnd(REMOTING__REPLY_NAME, Poco::RemotingNG::SerializerBase::MESSAGE_REPLY);
		}
		catch (Poco::Exception& e)
		{
			if (!remoting__requestSucceeded)
			{
				Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_FAULT);
				remoting__ser.serializeFaultMessage(REMOTING__NAMES[0], e);
			}
		}
		catch (std::exception& e)
		{
			if (!remoting__requestSucceeded)
			{
				Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_FAULT);
				Poco::Exception exc(e.what());
				remoting__ser.serializeFaultMessage(REMOTING__NAMES[0], exc);
			}
		}
		catch (...)
		{
			if (!remoting__requestSucceeded)
			{
				Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_FAULT);
				Poco::Exception exc("Unknown Exception");
				remoting__ser.serializeFaultMessage(REMOTING__NAMES[0], exc);
			}
		}
	}

};


class UnitsOfMeasureServiceFindPrefixMethodHandler: public Poco::RemotingNG::MethodHandler
{
public:
	void invoke(Poco::RemotingNG::ServerTransport& remoting__trans, Poco::RemotingNG::Deserializer& remoting__deser, Poco::RemotingNG::RemoteObject::Ptr remoting__pRemoteObject)
	{
		using namespace std::string_literals;
		
		static const std::string REMOTING__NAMES[] = {"findPrefix"s,"code"s};
		bool remoting__requestSucceeded = false;
		try
		{
			std::string code;
			remoting__deser.deserializeMessageBegin(REMOTING__NAMES[0], Poco::RemotingNG::SerializerBase::MESSAGE_REQUEST);
			Poco::RemotingNG::TypeDeserializer<std::string >::deserialize(REMOTING__NAMES[1], true, remoting__deser, code);
			remoting__deser.deserializeMessageEnd(REMOTING__NAMES[0], Poco::RemotingNG::SerializerBase::MESSAGE_REQUEST);
			IoT::UnitsOfMeasure::UnitsOfMeasureServiceRemoteObject* remoting__pCastedRO = static_cast<IoT::UnitsOfMeasure::UnitsOfMeasureServiceRemoteObject*>(remoting__pRemoteObject.get());
			Poco::SharedPtr < IoT::UnitsOfMeasure::Prefix > remoting__return = remoting__pCastedRO->findPrefix(code);
			remoting__requestSucceeded = true;
			Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_REPLY);
			static const std::string REMOTING__REPLY_NAME("findPrefixReply");
			remoting__ser.serializeMessageBegin(REMOTING__REPLY_NAME, Poco::RemotingNG::SerializerBase::MESSAGE_REPLY);
			Poco::RemotingNG::TypeSerializer<Poco::SharedPtr < IoT::UnitsOfMeasure::Prefix > >::serialize(Poco::RemotingNG::SerializerBase::RETURN_PARAM, remoting__return, remoting__ser);
			remoting__ser.serializeMessageEnd(REMOTING__REPLY_NAME, Poco::RemotingNG::SerializerBase::MESSAGE_REPLY);
		}
		catch (Poco::Exception& e)
		{
			if (!remoting__requestSucceeded)
			{
				Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_FAULT);
				remoting__ser.serializeFaultMessage(REMOTING__NAMES[0], e);
			}
		}
		catch (std::exception& e)
		{
			if (!remoting__requestSucceeded)
			{
				Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_FAULT);
				Poco::Exception exc(e.what());
				remoting__ser.serializeFaultMessage(REMOTING__NAMES[0], exc);
			}
		}
		catch (...)
		{
			if (!remoting__requestSucceeded)
			{
				Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_FAULT);
				Poco::Exception exc("Unknown Exception");
				remoting__ser.serializeFaultMessage(REMOTING__NAMES[0], exc);
			}
		}
	}

};


class UnitsOfMeasureServiceFindUnitMethodHandler: public Poco::RemotingNG::MethodHandler
{
public:
	void invoke(Poco::RemotingNG::ServerTransport& remoting__trans, Poco::RemotingNG::Deserializer& remoting__deser, Poco::RemotingNG::RemoteObject::Ptr remoting__pRemoteObject)
	{
		using namespace std::string_literals;
		
		static const std::string REMOTING__NAMES[] = {"findUnit"s,"code"s};
		bool remoting__requestSucceeded = false;
		try
		{
			std::string code;
			remoting__deser.deserializeMessageBegin(REMOTING__NAMES[0], Poco::RemotingNG::SerializerBase::MESSAGE_REQUEST);
			Poco::RemotingNG::TypeDeserializer<std::string >::deserialize(REMOTING__NAMES[1], true, remoting__deser, code);
			remoting__deser.deserializeMessageEnd(REMOTING__NAMES[0], Poco::RemotingNG::SerializerBase::MESSAGE_REQUEST);
			IoT::UnitsOfMeasure::UnitsOfMeasureServiceRemoteObject* remoting__pCastedRO = static_cast<IoT::UnitsOfMeasure::UnitsOfMeasureServiceRemoteObject*>(remoting__pRemoteObject.get());
			Poco::SharedPtr < IoT::UnitsOfMeasure::Unit > remoting__return = remoting__pCastedRO->findUnit(code);
			remoting__requestSucceeded = true;
			Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_REPLY);
			static const std::string REMOTING__REPLY_NAME("findUnitReply");
			remoting__ser.serializeMessageBegin(REMOTING__REPLY_NAME, Poco::RemotingNG::SerializerBase::MESSAGE_REPLY);
			Poco::RemotingNG::TypeSerializer<Poco::SharedPtr < IoT::UnitsOfMeasure::Unit > >::serialize(Poco::RemotingNG::SerializerBase::RETURN_PARAM, remoting__return, remoting__ser);
			remoting__ser.serializeMessageEnd(REMOTING__REPLY_NAME, Poco::RemotingNG::SerializerBase::MESSAGE_REPLY);
		}
		catch (Poco::Exception& e)
		{
			if (!remoting__requestSucceeded)
			{
				Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_FAULT);
				remoting__ser.serializeFaultMessage(REMOTING__NAMES[0], e);
			}
		}
		catch (std::exception& e)
		{
			if (!remoting__requestSucceeded)
			{
				Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_FAULT);
				Poco::Exception exc(e.what());
				remoting__ser.serializeFaultMessage(REMOTING__NAMES[0], exc);
			}
		}
		catch (...)
		{
			if (!remoting__requestSucceeded)
			{
				Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_FAULT);
				Poco::Exception exc("Unknown Exception");
				remoting__ser.serializeFaultMessage(REMOTING__NAMES[0], exc);
			}
		}
	}

};


class UnitsOfMeasureServiceFormatMethodHandler: public Poco::RemotingNG::MethodHandler
{
public:
	void invoke(Poco::RemotingNG::ServerTransport& remoting__trans, Poco::RemotingNG::Deserializer& remoting__deser, Poco::RemotingNG::RemoteObject::Ptr remoting__pRemoteObject)
	{
		using namespace std::string_literals;
		
		static const std::string REMOTING__NAMES[] = {"format"s,"prefixedCode"s};
		bool remoting__requestSucceeded = false;
		try
		{
			std::string prefixedCode;
			remoting__deser.deserializeMessageBegin(REMOTING__NAMES[0], Poco::RemotingNG::SerializerBase::MESSAGE_REQUEST);
			Poco::RemotingNG::TypeDeserializer<std::string >::deserialize(REMOTING__NAMES[1], true, remoting__deser, prefixedCode);
			remoting__deser.deserializeMessageEnd(REMOTING__NAMES[0], Poco::RemotingNG::SerializerBase::MESSAGE_REQUEST);
			IoT::UnitsOfMeasure::UnitsOfMeasureServiceRemoteObject* remoting__pCastedRO = static_cast<IoT::UnitsOfMeasure::UnitsOfMeasureServiceRemoteObject*>(remoting__pRemoteObject.get());
			std::string remoting__return = remoting__pCastedRO->format(prefixedCode);
			remoting__requestSucceeded = true;
			Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_REPLY);
			static const std::string REMOTING__REPLY_NAME("formatReply");
			remoting__ser.serializeMessageBegin(REMOTING__REPLY_NAME, Poco::RemotingNG::SerializerBase::MESSAGE_REPLY);
			Poco::RemotingNG::TypeSerializer<std::string >::serialize(Poco::RemotingNG::SerializerBase::RETURN_PARAM, remoting__return, remoting__ser);
			remoting__ser.serializeMessageEnd(REMOTING__REPLY_NAME, Poco::RemotingNG::SerializerBase::MESSAGE_REPLY);
		}
		catch (Poco::Exception& e)
		{
			if (!remoting__requestSucceeded)
			{
				Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_FAULT);
				remoting__ser.serializeFaultMessage(REMOTING__NAMES[0], e);
			}
		}
		catch (std::exception& e)
		{
			if (!remoting__requestSucceeded)
			{
				Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_FAULT);
				Poco::Exception exc(e.what());
				remoting__ser.serializeFaultMessage(REMOTING__NAMES[0], exc);
			}
		}
		catch (...)
		{
			if (!remoting__requestSucceeded)
			{
				Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_FAULT);
				Poco::Exception exc("Unknown Exception");
				remoting__ser.serializeFaultMessage(REMOTING__NAMES[0], exc);
			}
		}
	}

};


class UnitsOfMeasureServiceResolveMethodHandler: public Poco::RemotingNG::MethodHandler
{
public:
	void invoke(Poco::RemotingNG::ServerTransport& remoting__trans, Poco::RemotingNG::Deserializer& remoting__deser, Poco::RemotingNG::RemoteObject::Ptr remoting__pRemoteObject)
	{
		using namespace std::string_literals;
		
		static const std::string REMOTING__NAMES[] = {"resolve"s,"prefixedCode"s};
		bool remoting__requestSucceeded = false;
		try
		{
			std::string prefixedCode;
			remoting__deser.deserializeMessageBegin(REMOTING__NAMES[0], Poco::RemotingNG::SerializerBase::MESSAGE_REQUEST);
			Poco::RemotingNG::TypeDeserializer<std::string >::deserialize(REMOTING__NAMES[1], true, remoting__deser, prefixedCode);
			remoting__deser.deserializeMessageEnd(REMOTING__NAMES[0], Poco::RemotingNG::SerializerBase::MESSAGE_REQUEST);
			IoT::UnitsOfMeasure::UnitsOfMeasureServiceRemoteObject* remoting__pCastedRO = static_cast<IoT::UnitsOfMeasure::UnitsOfMeasureServiceRemoteObject*>(remoting__pRemoteObject.get());
			IoT::UnitsOfMeasure::PrefixedUnit remoting__return = remoting__pCastedRO->resolve(prefixedCode);
			remoting__requestSucceeded = true;
			Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_REPLY);
			static const std::string REMOTING__REPLY_NAME("resolveReply");
			remoting__ser.serializeMessageBegin(REMOTING__REPLY_NAME, Poco::RemotingNG::SerializerBase::MESSAGE_REPLY);
			Poco::RemotingNG::TypeSerializer<IoT::UnitsOfMeasure::PrefixedUnit >::serialize(Poco::RemotingNG::SerializerBase::RETURN_PARAM, remoting__return, remoting__ser);
			remoting__ser.serializeMessageEnd(REMOTING__REPLY_NAME, Poco::RemotingNG::SerializerBase::MESSAGE_REPLY);
		}
		catch (Poco::Exception& e)
		{
			if (!remoting__requestSucceeded)
			{
				Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_FAULT);
				remoting__ser.serializeFaultMessage(REMOTING__NAMES[0], e);
			}
		}
		catch (std::exception& e)
		{
			if (!remoting__requestSucceeded)
			{
				Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_FAULT);
				Poco::Exception exc(e.what());
				remoting__ser.serializeFaultMessage(REMOTING__NAMES[0], exc);
			}
		}
		catch (...)
		{
			if (!remoting__requestSucceeded)
			{
				Poco::RemotingNG::Serializer& remoting__ser = remoting__trans.sendReply(Poco::RemotingNG::SerializerBase::MESSAGE_FAULT);
				Poco::Exception exc("Unknown Exception");
				remoting__ser.serializeFaultMessage(REMOTING__NAMES[0], exc);
			}
		}
	}

};


UnitsOfMeasureServiceSkeleton::UnitsOfMeasureServiceSkeleton():
	Poco::RemotingNG::Skeleton()

{
	using namespace std::string_literals;
	
	addMethodHandler("canonicalize"s, new IoT::UnitsOfMeasure::UnitsOfMeasureServiceCanonicalizeMethodHandler);
	addMethodHandler("convert"s, new IoT::UnitsOfMeasure::UnitsOfMeasureServiceConvertMethodHandler);
	addMethodHandler("findPrefix"s, new IoT::UnitsOfMeasure::UnitsOfMeasureServiceFindPrefixMethodHandler);
	addMethodHandler("findUnit"s, new IoT::UnitsOfMeasure::UnitsOfMeasureServiceFindUnitMethodHandler);
	addMethodHandler("format"s, new IoT::UnitsOfMeasure::UnitsOfMeasureServiceFormatMethodHandler);
	addMethodHandler("resolve"s, new IoT::UnitsOfMeasure::UnitsOfMeasureServiceResolveMethodHandler);
}


UnitsOfMeasureServiceSkeleton::~UnitsOfMeasureServiceSkeleton()
{
}


const std::string UnitsOfMeasureServiceSkeleton::DEFAULT_NS;
} // namespace UnitsOfMeasure
} // namespace IoT

