#include <ns3/applications-module.h>
#include <ns3/core-module.h>
#include <ns3/internet-module.h>
#include <ns3/log.h>
#include <ns3/network-module.h>
#include <ns3/point-to-point-module.h>
#include <ns3/random-variable-stream.h>

#include <chrono>
#include <iomanip>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P2PoolSim");

// Share structure to represent a share in the sharechain
struct Share
{
    std::string hash;                // Unique identifier for the share
    uint32_t height;                 // Height in the sharechain
    double timestamp;                // Creation time
    std::string parentHash;          // Hash of the parent share
    std::vector<std::string> uncles; // List of uncle share hashes

    Share(std::string h, uint32_t ht, double ts, std::string ph, std::vector<std::string> u)
        : hash(h),
          height(ht),
          timestamp(ts),
          parentHash(ph),
          uncles(u)
    {
    }
};

// Sharechain class to manage shares and track metrics
class Sharechain
{
public:
    void AddShare(const Share &share, double currentTime)
    {
        // Check for duplicate shares
        if (shares_.find(share.hash) != shares_.end())
        {
            return;
        }
        // Validate share: ensure parent exists and height is correct
        if (share.parentHash.empty() || shares_.find(share.parentHash) != shares_.end())
        {
            uint32_t expectedHeight =
                share.parentHash.empty() ? 0 : shares_[share.parentHash].height + 1;
            if (share.height == expectedHeight)
            {
                shares_[share.hash] = share;
                // Count valid uncles
                for (const auto &uncleHash : share.uncles)
                {
                    if (shares_.find(uncleHash) != shares_.end() &&
                        IsUncleValid(uncleHash, share.height))
                    {
                        uncleCount_++;
                    }
                }
            }
            else
            {
                orphanCount_++; // Invalid height
            }
        }
        else
        {
            orphanCount_++; // Parent not found
        }
    }

    uint32_t GetUncleCount() const
    {
        return uncleCount_;
    }

    uint32_t GetOrphanCount() const
    {
        return orphanCount_;
    }

    uint32_t GetTotalShares() const
    {
        return shares_.size();
    }

private:
    bool IsUncleValid(const std::string &uncleHash, uint32_t currentHeight)
    {
        auto it = shares_.find(uncleHash);
        if (it != shares_.end())
        {
            uint32_t uncleHeight = it->second.height;
            return (currentHeight - uncleHeight <= 7); // Uncle window of 7 blocks
        }
        return false;
    }

    std::map<std::string, Share> shares_; // Hash -> Share mapping
    uint32_t uncleCount_ = 0;             // Total uncles included
    uint32_t orphanCount_ = 0;            // Total orphans rejected
};

// P2PoolApp: Custom application for each node
class P2PoolApp : public Application
{
public:
    P2PoolApp()
        : shareCount_(0),
          socket_(nullptr),
          peers_(),
          sharechain_()
    {
        shareDist_ = CreateObject<NormalRandomVariable>();
        latencyDist_ = CreateObject<NormalRandomVariable>();
    }

    void Setup(uint32_t nodeId,
               Ptr<Socket> socket,
               std::vector<Ipv4Address> peers,
               double shareMean,
               double shareStd,
               double latencyMean,
               double latencyStd)
    {
        nodeId_ = nodeId;
        socket_ = socket;
        peers_ = peers;
        shareDist_->SetAttribute("Mean", DoubleValue(shareMean));
        shareDist_->SetAttribute("Variance", DoubleValue(shareStd * shareStd));
        latencyDist_->SetAttribute("Mean", DoubleValue(latencyMean));
        latencyDist_->SetAttribute("Variance", DoubleValue(latencyStd * latencyStd));
        socket_->SetRecvCallback(MakeCallback(&P2PoolApp::HandleReceive, this));
    }

private:
    void StartApplication() override
    {
        ScheduleShare();
    }

    void ScheduleShare()
    {
        double delay = shareDist_->GetValue();
        Simulator::Schedule(Seconds(std::max(0.1, delay)), &P2PoolApp::GenerateShare, this);
    }

    void GenerateShare()
    {
        shareCount_++;
        std::string parentHash = GetLatestShareHash();
        uint32_t height = parentHash.empty() ? 0 : sharechain_.shares_[parentHash].height + 1;
        std::string hash = GenerateHash();
        double timestamp = Simulator::Now().GetSeconds();
        std::vector<std::string> uncles = GetUncles(height);
        Share newShare(hash, height, timestamp, parentHash, uncles);
        sharechain_.AddShare(newShare, timestamp);
        NS_LOG_INFO("Node " << nodeId_ << " generated share: " << hash << " at height " << height);
        BroadcastShare(newShare);
        ScheduleShare();
    }

    std::string GetLatestShareHash()
    {
        if (sharechain_.shares_.empty())
        {
            return "";
        }
        auto it = std::max_element(
            sharechain_.shares_.begin(),
            sharechain_.shares_.end(),
            [](const auto &a, const auto &b)
            { return a.second.height < b.second.height; });
        return it->first;
    }

    std::vector<std::string> GetUncles(uint32_t currentHeight)
    {
        std::vector<std::string> uncles;
        for (const auto &pair : sharechain_.shares_)
        {
            if (pair.second.height < currentHeight && currentHeight - pair.second.height <= 7)
            {
                uncles.push_back(pair.first);
                if (uncles.size() >= 2)
                {
                    break; // Limit to 2 uncles per share
                }
            }
        }
        return uncles;
    }

    std::string GenerateHash()
    {
        std::stringstream ss;
        ss << "share-" << nodeId_ << "-" << shareCount_ << "-" << std::fixed << std::setprecision(6)
           << Simulator::Now().GetSeconds();
        return ss.str();
    }

    void BroadcastShare(const Share &share)
    {
        std::string shareData = SerializeShare(share);
        for (const auto &peer : peers_)
        {
            Ptr<Packet> packet = Create<Packet>((uint8_t *)shareData.c_str(), shareData.size());
            double latency = latencyDist_->GetValue();
            Simulator::Schedule(Seconds(std::max(0.01, latency)),
                                &P2PoolApp::SendPacket,
                                this,
                                packet,
                                peer);
        }
    }

    void SendPacket(Ptr<Packet> packet, Ipv4Address peer)
    {
        socket_->SendTo(packet, 0, InetSocketAddress(peer, 9000));
    }

    void HandleReceive(Ptr<Socket> socket)
    {
        Ptr<Packet> packet;
        while ((packet = socket->Recv()))
        {
            uint8_t buffer[1024];
            packet->CopyData(buffer, packet->GetSize());
            std::string shareData(buffer, buffer + packet->GetSize());
            Share receivedShare = DeserializeShare(shareData);
            double currentTime = Simulator::Now().GetSeconds();
            sharechain_.AddShare(receivedShare, currentTime);
            NS_LOG_INFO("Node " << nodeId_ << " received share: " << receivedShare.hash);
        }
    }

    std::string SerializeShare(const Share &share)
    {
        std::stringstream ss;
        ss << share.hash << "|" << share.height << "|" << share.timestamp << "|"
           << share.parentHash;
        for (const auto &uncle : share.uncles)
        {
            ss << "|" << uncle;
        }
        return ss.str();
    }

    Share DeserializeShare(const std::string &data)
    {
        std::stringstream ss(data);
        std::string hash, parentHash, token;
        uint32_t height;
        double timestamp;
        std::vector<std::string> uncles;
        std::getline(ss, hash, '|');
        std::getline(ss, token, '|');
        height = std::stoi(token);
        std::getline(ss, token, '|');
        timestamp = std::stod(token);
        std::getline(ss, parentHash, '|');
        while (std::getline(ss, token, '|'))
        {
            uncles.push_back(token);
        }
        return Share(hash, height, timestamp, parentHash, uncles);
    }

    uint32_t nodeId_;                       // Unique node identifier
    uint32_t shareCount_;                   // Counter for shares generated by this node
    Ptr<Socket> socket_;                    // UDP socket for communication
    std::vector<Ipv4Address> peers_;        // List of peer IP addresses
    Ptr<NormalRandomVariable> shareDist_;   // Distribution for share intervals
    Ptr<NormalRandomVariable> latencyDist_; // Distribution for latency
    Sharechain sharechain_;                 // Local sharechain instance
};

// Main simulation function
int main(int argc, char *argv[])
{
    uint32_t nNodes = 100;       // Default number of nodes
    double latencyMean = 0.1;    // Mean latency in seconds
    double latencyStd = 0.02;    // Std dev of latency
    double shareMean = 10.0;     // Mean share production interval in seconds
    double shareStd = 2.0;       // Std dev of share production
    double simDuration = 3600.0; // Simulation duration in seconds

    // Parse command-line arguments
    CommandLine cmd;
    cmd.AddValue("nNodes", "Number of nodes", nNodes);
    cmd.AddValue("latencyMean", "Mean latency in seconds", latencyMean);
    cmd.AddValue("latencyStd", "Standard deviation of latency", latencyStd);
    cmd.AddValue("shareMean", "Mean share production interval", shareMean);
    cmd.AddValue("shareStd", "Standard deviation of share production", shareStd);
    cmd.AddValue("simDuration", "Simulation duration in seconds", simDuration);
    cmd.Parse(argc, argv);

    LogComponentEnable("P2PoolSim", LOG_LEVEL_INFO);

    // Create nodes
    NodeContainer nodes;
    nodes.Create(nNodes);

    // Set up point-to-point links
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("0ms")); // Latency handled in app

    // Install internet stack
    InternetStackHelper stack;
    stack.Install(nodes);

    // Assign IP addresses
    Ipv4AddressHelper address;
    address.SetBase("10.1.0.0", "255.255.0.0");

    std::vector<NetDeviceContainer> devices;
    std::vector<Ipv4InterfaceContainer> interfaces;
    std::vector<std::vector<Ipv4Address>> peers(nNodes);

    // Create a random mesh: each node connects to 4 peers
    std::mt19937 rng(std::chrono::system_clock::now().time_since_epoch().count());
    for (uint32_t i = 0; i < nNodes; ++i)
    {
        std::vector<uint32_t> peerIds;
        while (peerIds.size() < 4 && peerIds.size() < nNodes - 1)
        {
            uint32_t peer = rng() % nNodes;
            if (peer != i && std::find(peerIds.begin(), peerIds.end(), peer) == peerIds.end())
            {
                peerIds.push_back(peer);
            }
        }
        for (uint32_t peer : peerIds)
        {
            NodeContainer pair(nodes.Get(i), nodes.Get(peer));
            NetDeviceContainer dev = p2p.Install(pair);
            devices.push_back(dev);
            Ipv4InterfaceContainer iface = address.Assign(dev);
            interfaces.push_back(iface);
            peers[i].push_back(iface.GetAddress(1));
            peers[peer].push_back(iface.GetAddress(0));
            address.NewNetwork();
        }
    }

    // Install applications
    ApplicationContainer apps;
    for (uint32_t i = 0; i < nNodes; ++i)
    {
        Ptr<Socket> socket =
            Socket::CreateSocket(nodes.Get(i), TypeId::LookupByName("ns3::UdpSocketFactory"));
        socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 9000));
        Ptr<P2PoolApp> app = CreateObject<P2PoolApp>();
        app->Setup(i, socket, peers[i], shareMean, shareStd, latencyMean, latencyStd);
        nodes.Get(i)->AddApplication(app);
        apps.Add(app);
    }

    // Start and stop simulation
    apps.Start(Seconds(0.0));
    apps.Stop(Seconds(simDuration));

    Simulator::Run();

    // Collect and report metrics
    uint32_t totalShares = 0;
    uint32_t totalUncles = 0;
    uint32_t totalOrphans = 0;
    for (uint32_t i = 0; i < nNodes; ++i)
    {
        Ptr<P2PoolApp> app = DynamicCast<P2PoolApp>(apps.Get(i));
        totalShares += app->sharechain_.GetTotalShares();
        totalUncles += app->sharechain_.GetUncleCount();
        totalOrphans += app->sharechain_.GetOrphanCount();
    }

    double unclePercentage =
        (totalShares > 0) ? (static_cast<double>(totalUncles) / totalShares) * 100.0 : 0.0;
    double orphanPercentage =
        (totalShares > 0) ? (static_cast<double>(totalOrphans) / totalShares) * 100.0 : 0.0;

    std::cout << "Simulation Results:" << std::endl;
    std::cout << "Total Shares: " << totalShares << std::endl;
    std::cout << "Total Uncles: " << totalUncles << " (" << unclePercentage << "%)" << std::endl;
    std::cout << "Total Orphans: " << totalOrphans << " (" << orphanPercentage << "%)" << std::endl;

    Simulator::Destroy();
    return 0;
}