#include "config.h"

#include "mctp_endpoint_discovery.hpp"

#include "common/types.hpp"
#include "common/utils.hpp"

#include <phosphor-logging/lg2.hpp>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <string_view>
#include <vector>

using namespace sdbusplus::bus::match::rules;

PHOSPHOR_LOG2_USING;

namespace pldm
{
    
// Define the type for the property map
using PropertyType = std::variant<
    uint8_t,              // EID (DBus type: y)
    uint32_t,            // NetworkId (DBus type: u)
    std::vector<uint8_t> // SupportedMessageTypes (DBus type: ay)
>;
    
MctpDiscovery::MctpDiscovery(
    sdbusplus::bus_t& bus,
    std::initializer_list<MctpDiscoveryHandlerIntf*> list) :
    bus(bus), mctpEndpointAddedSignal(
                  bus, interfacesAdded("/au/com/codeconstruct/mctp1/networks"),
                  std::bind_front(&MctpDiscovery::discoverEndpoints, this)),
    mctpEndpointRemovedSignal(
        bus, interfacesRemoved("/au/com/codeconstruct/mctp1/networks"),
        std::bind_front(&MctpDiscovery::removeEndpoints, this)),
    handlers(list)
{
    getMctpInfos(existingMctpInfos);
    handleMctpEndpoints(existingMctpInfos);
}

void MctpDiscovery::getMctpInfos(MctpInfos& mctpInfos)
{
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
                            info(
                            "Adding Endpoint networkId '{NETWORK}' and EID '{EID}'",
                            "NETWORK", networkId, "EID", eid);
                            mctpInfos.emplace_back(
                                MctpInfo(eid, emptyUUID, "", networkId));
                        }
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        error("error - {ERROR}","ERROR", e);
        return ;
    }
}

void MctpDiscovery::getAddedMctpInfos(sdbusplus::message_t& msg,
                                      MctpInfos& mctpInfos)
{
    using ObjectPath = sdbusplus::message::object_path;
    ObjectPath objPath;
    using Property = std::string;
    using PropertyMap = std::map<Property, dbus::Value>;
    std::map<std::string, PropertyMap> interfaces;

    try
    {
        msg.read(objPath, interfaces);
    }
    catch (const sdbusplus::exception_t& e)
    {
        error(
            "Error reading MCTP Endpoint added interface message, error - {ERROR}",
            "ERROR", e);
        return;
    }

    for (const auto& [intfName, properties] : interfaces)
    {
        if (intfName == "xyz.openbmc_project.MCTP.Endpoint")
        {
            if (properties.contains("NetworkId") &&
                properties.contains("EID") &&
                properties.contains("SupportedMessageTypes"))
            {
                auto networkId =
                    std::get<NetworkId>(properties.at("NetworkId"));
                auto eid = std::get<mctp_eid_t>(properties.at("EID"));
                auto types = std::get<std::vector<uint8_t>>(
                    properties.at("SupportedMessageTypes"));
                if (std::find(types.begin(), types.end(), mctpTypePLDM) !=
                    types.end())
                {
                    info(
                        "Adding Endpoint networkId '{NETWORK}' and EID '{EID}'",
                        "NETWORK", networkId, "EID", eid);
                    mctpInfos.emplace_back(
                        MctpInfo(eid, emptyUUID, "", networkId));
                }
            }
        }
    }
}

void MctpDiscovery::addToExistingMctpInfos(const MctpInfos& addedInfos)
{
    for (const auto& mctpInfo : addedInfos)
    {
        if (std::find(existingMctpInfos.begin(), existingMctpInfos.end(),
                      mctpInfo) == existingMctpInfos.end())
        {
            existingMctpInfos.emplace_back(mctpInfo);
        }
    }
}

void MctpDiscovery::removeFromExistingMctpInfos(MctpInfos& mctpInfos,
                                                MctpInfos& removedInfos)
{
    for (const auto& mctpInfo : existingMctpInfos)
    {
        if (std::find(mctpInfos.begin(), mctpInfos.end(), mctpInfo) ==
            mctpInfos.end())
        {
            removedInfos.emplace_back(mctpInfo);
        }
    }
    for (const auto& mctpInfo : removedInfos)
    {
        info("Removing Endpoint networkId '{NETWORK}' and  EID '{EID}'",
             "NETWORK", std::get<3>(mctpInfo), "EID", std::get<0>(mctpInfo));
        existingMctpInfos.erase(std::remove(existingMctpInfos.begin(),
                                            existingMctpInfos.end(), mctpInfo),
                                existingMctpInfos.end());
    }
}

void MctpDiscovery::discoverEndpoints(sdbusplus::message_t& msg)
{
    MctpInfos addedInfos;
    getAddedMctpInfos(msg, addedInfos);
    addToExistingMctpInfos(addedInfos);
    handleMctpEndpoints(addedInfos);
}

void MctpDiscovery::removeEndpoints(sdbusplus::message_t&)
{
    MctpInfos mctpInfos;
    MctpInfos removedInfos;
    getMctpInfos(mctpInfos);
    removeFromExistingMctpInfos(mctpInfos, removedInfos);
    handleRemovedMctpEndpoints(removedInfos);
}

void MctpDiscovery::handleMctpEndpoints(const MctpInfos& mctpInfos)
{
    for (const auto& handler : handlers)
    {
        if (handler)
        {
            handler->handleMctpEndpoints(mctpInfos);
        }
    }
}

void MctpDiscovery::handleRemovedMctpEndpoints(const MctpInfos& mctpInfos)
{
    for (const auto& handler : handlers)
    {
        if (handler)
        {
            handler->handleRemovedMctpEndpoints(mctpInfos);
        }
    }
}

} // namespace pldm
