#include "common/transport.hpp"

#include <libpldm/transport.h>
#include <libpldm/transport/af-mctp.h>
#include <libpldm/transport/mctp-demux.h>

#include <algorithm>
#include <ranges>
#include <system_error>
#include <iostream>
#include <map>
#include <vector>
#include <sdbusplus/server.hpp>

using namespace sdbusplus::bus::match::rules;

struct pldm_transport* transport_impl_init(TransportImpl& impl, pollfd& pollfd);
void transport_impl_destroy(TransportImpl& impl);
using PropertyType = std::variant<
    uint8_t,              // EID (DBus type: y)
    uint32_t,            // NetworkId (DBus type: u)
    std::vector<uint8_t> // SupportedMessageTypes (DBus type: ay)
>;
static constexpr uint8_t mctpTypePLDM = 1;

static constexpr uint8_t MCTP_EID_VALID_MIN = 8;
static constexpr uint8_t MCTP_EID_VALID_MAX = 255;

/*
 * Currently the OpenBMC ecosystem assumes TID == EID. Pre-populate the TID
 * mappings over the EID space excluding the Null (0), Reserved (1 to 7),
 * Broadcast EIDs (255) defined by Section 8.2 Special endpoint IDs in DSP0236
 * v1.3.1. Further, by Section 8.1.1 SetTID command (0x01) in DSP0240 v1.1.0,
 * the TIDs 0x00 and 0xff are also reserved. These overlap with the reserved
 * EIDs so no additional filtering is required.
 *
 * Further, pldmtool and pldmd are two separate processes. They are opening two
 * different sockets, but with the mctp-demux-daemon, the response messages are
 * broadcasted to all sockets. When pldmd receives the response for a request
 * issued by pldmtool, pldm_transport_mctp_demux_recv() may return with error
 * PLDM_REQUESTER_RECV_FAIL if it fails to map the EID of the source endpoint to
 * its TID. The EID to TID mappings of pldmtool and pldmd should be coherent to
 * prevent the failure of pldm_transport_mctp_demux_recv().
 */
static void discoverMCTP(std::map < uint8_t , uint8_t > * eid_network_map){
    
    // Find all implementations of the MCTP Endpoint interface
    try {
        // Create a D-Bus connection to the system bus
        
        auto bus = sdbusplus::bus::new_default();

        // Step 1: Query the subtree for MCTP endpoints
        auto methodCall = bus.new_method_call(
            "xyz.openbmc_project.ObjectMapper",  // Service name
            "/xyz/openbmc_project/object_mapper", // Object path
            "xyz.openbmc_project.ObjectMapper",  // Interface name
            "GetSubTree"                         // Method name
        );

        // Search the networks path for endpoints with the MCTP interface
        std::string searchPath = "/au/com/codeconstruct/mctp1/networks";
        methodCall.append(searchPath, 0, std::vector<std::string>({"xyz.openbmc_project.MCTP.Endpoint"}));

        // Send the method call and get the reply
        auto reply = bus.call(methodCall);

        // Parse the reply into a map of object paths to services and interfaces
        using SubTreeType = std::map<std::string, std::map<std::string, std::vector<std::string>>>;
        SubTreeType subtree;
        reply.read(subtree);

        // Step 2: Loop over the results and query each endpoint's properties
        for (const auto& [objectPath, serviceMap] : subtree) {
            for (const auto& [serviceName, interfaces] : serviceMap) {
                if (std::find(interfaces.begin(), interfaces.end(),
                              "xyz.openbmc_project.MCTP.Endpoint") != interfaces.end()) {
                    // Create a method call to get all properties of the interface
                    auto propCall = bus.new_method_call(
                        serviceName.c_str(),                  // Service name
                        objectPath.c_str(),                   // Object path
                        "org.freedesktop.DBus.Properties",    // Interface name
                        "GetAll"                              // Method name
                    );

                    // Specify the interface we want the properties of
                    propCall.append("xyz.openbmc_project.MCTP.Endpoint");

                    // Send the method call and get the reply
                    auto propReply = bus.call(propCall);

                    // Parse the reply (map of property names to variants)
                    std::map<std::string, PropertyType> properties;
                    propReply.read(properties);

                    if (properties.contains("NetworkId") &&
                    properties.contains("EID") &&
                    properties.contains("SupportedMessageTypes"))
                        {
                        auto networkId =
                            std::get<uint32_t>(properties.at("NetworkId"));
                        auto eid = std::get<uint8_t>(properties.at("EID"));
                        auto types = std::get<std::vector<uint8_t>>(
                            properties.at("SupportedMessageTypes"));
                        if (std::find(types.begin(), types.end(), mctpTypePLDM) !=
                            types.end())
                        {
                            (*eid_network_map)[eid] = networkId;
                        }
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        std::cout<<"Error" <<std::endl; 
        return ;
    }
}
[[maybe_unused]] static struct pldm_transport*
    pldm_transport_impl_mctp_demux_init(TransportImpl& impl, pollfd& pollfd)
{
    impl.mctp_demux = nullptr;
    pldm_transport_mctp_demux_init(&impl.mctp_demux);
    if (!impl.mctp_demux)
    {
        return nullptr;
    }

    for (const auto eid :
         std::views::iota(MCTP_EID_VALID_MIN, MCTP_EID_VALID_MAX))
    {
        int rc = pldm_transport_mctp_demux_map_tid(impl.mctp_demux, eid, eid);
        if (rc)
        {
            pldm_transport_af_mctp_destroy(impl.af_mctp);
            return nullptr;
        }
    }

    pldm_transport* pldmTransport =
        pldm_transport_mctp_demux_core(impl.mctp_demux);

    if (pldmTransport != nullptr)
    {
        pldm_transport_mctp_demux_init_pollfd(pldmTransport, &pollfd);
    }

    return pldmTransport;
}

[[maybe_unused]] static struct pldm_transport*
    pldm_transport_impl_af_mctp_init(TransportImpl& impl, pollfd& pollfd)
{
    impl.af_mctp = nullptr;
    pldm_transport_af_mctp_init(&impl.af_mctp);
    if (!impl.af_mctp)
    {
        return nullptr;
    }
    std::map < uint8_t , uint8_t > eid_network_map;
    discoverMCTP(&eid_network_map);
    for (const auto eid :
         std::views::iota(MCTP_EID_VALID_MIN, MCTP_EID_VALID_MAX))
    {
        
        if(!eid_network_map.contains(eid)){
            continue;
        }
        int rc = pldm_transport_af_mctp_map_tid(impl.af_mctp, eid, eid,eid_network_map[eid]);
        if (rc)
        {
            pldm_transport_af_mctp_destroy(impl.af_mctp);
            return nullptr;
        }
    }

    /* Listen for requests on any interface */
    if (pldm_transport_af_mctp_bind(impl.af_mctp, nullptr, 0))
    {
        return nullptr;
    }

    pldm_transport* pldmTransport = pldm_transport_af_mctp_core(impl.af_mctp);

    if (pldmTransport != nullptr)
    {
        pldm_transport_af_mctp_init_pollfd(pldmTransport, &pollfd);
    }

    return pldmTransport;
}

struct pldm_transport* transport_impl_init(TransportImpl& impl, pollfd& pollfd)
{
#if defined(PLDM_TRANSPORT_WITH_MCTP_DEMUX)
    return pldm_transport_impl_mctp_demux_init(impl, pollfd);
#elif defined(PLDM_TRANSPORT_WITH_AF_MCTP)
    return pldm_transport_impl_af_mctp_init(impl, pollfd);
#else
    return nullptr;
#endif
}

void transport_impl_destroy(TransportImpl& impl)
{
#if defined(PLDM_TRANSPORT_WITH_MCTP_DEMUX)
    pldm_transport_mctp_demux_destroy(impl.mctp_demux);
#elif defined(PLDM_TRANSPORT_WITH_AF_MCTP)
    pldm_transport_af_mctp_destroy(impl.af_mctp);
#endif
}

PldmTransport::PldmTransport()
{
    transport = transport_impl_init(impl, pfd);
    if (!transport)
    {
        throw std::system_error(ENOMEM, std::generic_category());
    }
}

PldmTransport::~PldmTransport()
{
    transport_impl_destroy(impl);
}

int PldmTransport::getEventSource() const
{
    return pfd.fd;
}

pldm_requester_rc_t PldmTransport::sendMsg(pldm_tid_t tid, const void* tx,
                                           size_t len)
{
   return pldm_transport_send_msg(transport, tid, tx, len);
}

pldm_requester_rc_t PldmTransport::recvMsg(pldm_tid_t& tid, void*& rx,
                                           size_t& len)
{
    return pldm_transport_recv_msg(transport, &tid, (void**)&rx, &len);
}

pldm_requester_rc_t PldmTransport::sendRecvMsg(
    pldm_tid_t tid, const void* tx, size_t txLen, void*& rx, size_t& rxLen)
{
     return pldm_transport_send_recv_msg(transport, tid, tx, txLen, &rx, &rxLen);
}
