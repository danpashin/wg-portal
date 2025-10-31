
export function freshInterface() {
  return {
    Disabled: false,
    DisplayName: "",
    Identifier: "",
    Mode: "server",
    Backend: "local",

    PublicKey: "",
    PrivateKey: "",

    ListenPort:  51820,
    Addresses: [],
    DnsStr: [],
    DnsSearch: [],

    Mtu: 0,
    FirewallMark: 0,
    RoutingTable: "",

    PreUp: "",
    PostUp: "",
    PreDown: "",
    PostDown: "",

    SaveConfig: false,

    // Peer defaults

    PeerDefNetwork: [],
    PeerDefDns: [],
    PeerDefDnsSearch: [],
    PeerDefEndpoint: "",
    PeerDefAllowedIPs: [],
    PeerDefMtu: 0,
    PeerDefPersistentKeepalive: 0,
    PeerDefFirewallMark: 0,
    PeerDefRoutingTable: "",
    PeerDefPreUp: "",
    PeerDefPostUp: "",
    PeerDefPreDown: "",
    PeerDefPostDown: "",

    TotalPeers: 0,
    EnabledPeers: 0,
    Filename: "",
    AdvancedSecurity: {
      jc: 0,
      jmin: 0,
      jmax: 0,
      s1: 0,
      s2: 0,
      s3: 0,
      s4: 0,
      h1: "1",
      h2: "2",
      h3: "3",
      h4: "4",
      i1: null,
      i2: null,
      i3: null,
      i4: null,
      i5: null,
    },
    UsesAdvancedSecurity: false,
  }
}

export function freshPeer() {
  return {
    Identifier: "",
    DisplayName: "",
    UserIdentifier: "",
    UserDisplayName: "",
    InterfaceIdentifier: "",
    Disabled: false,
    ExpiresAt: null,
    Notes: "",

    Endpoint: {
      Value: "",
      Overridable: true,
    },
    EndpointPublicKey: {
      Value: "",
      Overridable: true,
    },
    AllowedIPs: {
      Value: [],
      Overridable: true,
    },
    ExtraAllowedIPs: [],
    PresharedKey: "",
    PersistentKeepalive: {
      Value: 0,
      Overridable: true,
    },

    PrivateKey: "",
    PublicKey: "",

    Mode: "client",

    Addresses: [],
    CheckAliveAddress: "",
    Dns: {
      Value: [],
      Overridable: true,
    },
    DnsSearch: {
      Value: [],
      Overridable: true,
    },
    Mtu: {
      Value: 0,
      Overridable: true,
    },
    FirewallMark: {
      Value: 0,
      Overridable: true,
    },
    RoutingTable: {
      Value: "",
      Overridable: true,
    },

    PreUp: {
      Value: "",
      Overridable: true,
    },
    PostUp: {
      Value: "",
      Overridable: true,
    },
    PreDown: {
      Value: "",
      Overridable: true,
    },
    PostDown: {
      Value: "",
      Overridable: true,
    },

    Filename: "",

    // Internal values
    IgnoreGlobalSettings: false,
    IsSelected: false
  }
}

export function freshUser() {
  return {
    Identifier: "",

    Email: "",
    Source: "db",
    IsAdmin: false,

    Firstname: "",
    Lastname: "",
    Phone: "",
    Department: "",
    Notes: "",

    Password: "",

    Disabled: false,
    DisabledReason: "",
    Locked: false,
    LockedReason: "",

    ApiEnabled: false,

    PeerCount: 0,

    // Internal values
    IsSelected: false
  }
}

export function freshStats() {
  return {
    IsConnected: false,
    IsPingable: false,
    LastHandshake: null,
    LastPing: null,
    LastSessionStart: null,
    BytesTransmitted: 0,
    BytesReceived: 0,
    EndpointAddress: ""
  }
}