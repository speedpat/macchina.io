#include "Poco/OSP/BundleActivator.h"
#include "Poco/OSP/BundleContext.h"
#include "Poco/OSP/ServiceRegistry.h"
#include "Poco/OSP/PreferencesService.h"
#include "Poco/ClassLibrary.h"
#include "Poco/Net/SocketAddress.h"
#include "Poco/Net/MulticastSocket.h"
#include "Poco/LogStream.h"


#include "Poco/DNSSD/DNSSDResponder.h"
#include "Poco/DNSSD/DNSSDBrowser.h"
#if POCO_OS == POCO_OS_LINUX && !defined(POCO_DNSSD_USE_BONJOUR)
#include "Poco/DNSSD/Avahi/Avahi.h"
#else
#include "Poco/DNSSD/Bonjour/Bonjour.h"
#endif

#include "Poco/Delegate.h"


namespace
{
    void* get_in_addr(sockaddr_storage* sa)
    {
        if (sa->ss_family == AF_INET)
            return &reinterpret_cast<sockaddr_in*>(sa)->sin_addr;

        if (sa->ss_family == AF_INET6)
            return &reinterpret_cast<sockaddr_in6*>(sa)->sin6_addr;

        return nullptr;
    }

    const std::string SeparatorLine(20, '-');
}

namespace NanoLeaf {


class BundleActivator: public Poco::OSP::BundleActivator
{
public:
    void start(Poco::OSP::BundleContext::Ptr pContext) override
    {
        context = pContext;
        Poco::OSP::ServiceRef::ConstPtr prefserviceRef = context->registry().findByName("osp.core.preferences");
        Poco::OSP::PreferencesService::Ptr prefService = prefserviceRef.get()->castedInstance<Poco::OSP::PreferencesService>();

        Poco::Logger& log = Poco::Logger::get("NanoLeaf");
        Poco::LogStream logger(log);
        logger << "Hello, world!" << std::endl;

        Poco::DNSSD::initializeDNSSD();

        responder = std::make_shared<Poco::DNSSD::DNSSDResponder>();

        responder->browser().browseError += Poco::delegate(this, &BundleActivator::onError);
        responder->browser().resolveError += Poco::delegate(this, &BundleActivator::onError);
        responder->browser().serviceFound += Poco::delegate(this, &BundleActivator::onServiceFound);
        responder->browser().serviceRemoved += Poco::delegate(this, &BundleActivator::onServiceRemoved);
        responder->browser().serviceResolved += Poco::delegate(this, &BundleActivator::onServiceResolved);
        responder->browser().browseDomainError         += Poco::delegate(this, &BundleActivator::onError);
        responder->browser().browseDomainFound         += Poco::delegate(this, &BundleActivator::onBrowseDomainFound);
        responder->browser().browseDomainRemoved       += Poco::delegate(this, &BundleActivator::onBrowseDomainRemoved);
        responder->browser().registrationDomainError   += Poco::delegate(this, &BundleActivator::onError);
        responder->browser().registrationDomainFound   += Poco::delegate(this, &BundleActivator::onRegistrationDomainFound);
        responder->browser().registrationDomainRemoved += Poco::delegate(this, &BundleActivator::onRegistrationDomainRemoved);
        responder->browser().hostResolveError          += Poco::delegate(this, &BundleActivator::onError);
        responder->browser().hostResolved              += Poco::delegate(this, &BundleActivator::onHostResolved);

        responder->start();

        responder->browser().browse("_nanoleafapi._tcp", "");
    }


    void stop(Poco::OSP::BundleContext::Ptr pContext) override
    {
        Poco::Logger& log = Poco::Logger::get("NanoLeaf");
        Poco::LogStream logger(log);
        logger.information("Goodbye!");
        context.reset();
        responder->stop();
        responder.reset();
        Poco::DNSSD::uninitializeDNSSD();
    }


private:
    static Poco::Net::NetworkInterface findActiveNetworkInterface()
    {
        auto ifs = Poco::Net::NetworkInterface::list();
        for (auto & it : ifs)
        {
            if (!it.address().isWildcard() && !it.address().isLoopback() && it.supportsIPv4()) return it;
        }
        throw Poco::IOException("No configured Ethernet interface found");
    }


    void onError(const void* sender, const Poco::DNSSD::DNSSDBrowser::ErrorEventArgs& args)
    {
        Poco::Logger& log = Poco::Logger::get("NanoLeaf");
        Poco::LogStream logger(log);
        logger.error() << args.error.message() << " (" << args.error.code() << ")" << std::endl;
    }

    void onServiceFound(const void* sender, const Poco::DNSSD::DNSSDBrowser::ServiceEventArgs& args)
    {
        Poco::Logger& log = Poco::Logger::get("NanoLeaf");
        Poco::LogStream logger(log);
        logger.information() << "Service Found: \n"
                  << "  Name:      " << args.service.name() << "\n"
                  << "  Domain:    " << args.service.domain() << "\n"
                  << "  Type:      " << args.service.type() << "\n"
                  << "  Interface: " << args.service.networkInterface() << "\n" << std::endl;

        reinterpret_cast<Poco::DNSSD::DNSSDBrowser*>(const_cast<void*>(sender))->resolve(args.service);
    }

    void onServiceRemoved(const void* sender, const Poco::DNSSD::DNSSDBrowser::ServiceEventArgs& args)
    {
        Poco::Logger& log = Poco::Logger::get("NanoLeaf");
        Poco::LogStream logger(log);
        logger.information() << "Service Removed: \n"
                  << "  Name:      " << args.service.name() << "\n"
                  << "  Domain:    " << args.service.domain() << "\n"
                  << "  Type:      " << args.service.type() << "\n"
                  << "  Interface: " << args.service.networkInterface() << "\n" << std::endl;
    }

    void onServiceResolved(const void* sender, const Poco::DNSSD::DNSSDBrowser::ServiceEventArgs& args)
    {
        Poco::Logger& log = Poco::Logger::get("NanoLeaf");
        Poco::LogStream logger(log);
        logger.information() << "Service Resolved: \n"
                  << "  Name:      " << args.service.name() << "\n"
                  << "  Full Name: " << args.service.fullName() << "\n"
                  << "  Domain:    " << args.service.domain() << "\n"
                  << "  Type:      " << args.service.type() << "\n"
                  << "  Interface: " << args.service.networkInterface() << "\n"
                  << "  Host:      " << args.service.host() << "\n"
                  << "  Port:      " << args.service.port() << "\n"
                  << "  Properties: \n";



        for (Poco::DNSSD::Service::Properties::ConstIterator it = args.service.properties().begin(); it != args.service.properties().end(); ++it)
        {
            logger.information() << "    " << it->first << ": " << it->second << "\n";
        }
        logger.information() << std::endl;

        reinterpret_cast<Poco::DNSSD::DNSSDBrowser*>(const_cast<void*>(sender))->resolveHost(args.service.host());
    }

    void onHostResolved(const void* sender, const Poco::DNSSD::DNSSDBrowser::ResolveHostEventArgs& args)
    {
        Poco::Logger& log = Poco::Logger::get("NanoLeaf");
        Poco::LogStream logger(log);
        logger.information() << "Host Resolved: \n"
                  << "  Host:      " << args.host << "\n"
                  << "  Interface: " << args.networkInterface << "\n"
                  << "  Address:   " << args.address.toString() << "\n"
                  << "  TTL:       " << args.ttl << "\n" << std::endl;
    }

    void onBrowseDomainFound(const void* sender, const Poco::DNSSD::DNSSDBrowser::DomainEventArgs& args)
    {
        Poco::Logger& log = Poco::Logger::get("NanoLeaf");
        Poco::LogStream logger(log);
        logger.information() << "Browse Domain Found:\n"
                  << "  Name:      " << args.domain.name() << "\n"
                  << "  Interface: " << args.domain.networkInterface() << "\n"
                  << "  Default:   " << args.domain.isDefault() << "\n" << std::endl;
    }

    void onBrowseDomainRemoved(const void* sender, const Poco::DNSSD::DNSSDBrowser::DomainEventArgs& args)
    {
        Poco::Logger& log = Poco::Logger::get("NanoLeaf");
        Poco::LogStream logger(log);
        logger.information() << "Browse Domain Removed:\n"
                  << "  Name:      " << args.domain.name() << "\n"
                  << "  Interface: " << args.domain.networkInterface() << "\n"
                  << "  Default:   " << args.domain.isDefault() << "\n" << std::endl;
    }

    void onRegistrationDomainFound(const void* sender, const Poco::DNSSD::DNSSDBrowser::DomainEventArgs& args)
    {
        Poco::Logger& log = Poco::Logger::get("NanoLeaf");
        Poco::LogStream logger(log);
        logger.information() << "Registration Domain Found:\n"
                  << "  Name:      " << args.domain.name() << "\n"
                  << "  Interface: " << args.domain.networkInterface() << "\n"
                  << "  Default:   " << args.domain.isDefault() << "\n" << std::endl;
    }

    void onRegistrationDomainRemoved(const void* sender, const Poco::DNSSD::DNSSDBrowser::DomainEventArgs& args)
    {
        Poco::Logger& log = Poco::Logger::get("NanoLeaf");
        Poco::LogStream logger(log);
        logger.information() << "Registration Domain Removed:\n"
                  << "  Name:      " << args.domain.name() << "\n"
                  << "  Interface: " << args.domain.networkInterface() << "\n"
                  << "  Default:   " << args.domain.isDefault() << "\n" << std::endl;
    }

    Poco::OSP::BundleContext::Ptr context;
    typedef std::shared_ptr<Poco::DNSSD::DNSSDResponder> DNSSDResponderPtr;
    DNSSDResponderPtr responder;
};



} // namespace NanoLeaf


POCO_BEGIN_MANIFEST(Poco::OSP::BundleActivator)
    POCO_EXPORT_CLASS(NanoLeaf::BundleActivator)
POCO_END_MANIFEST
