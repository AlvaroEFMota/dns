use std::net::Ipv4Addr;
type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(DnsRecord::A {
                    domain: domain,
                    addr: addr,
                    ttl: ttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::UNKNOWN {
                    domain: domain,
                    qtype: qtype_num,
                    data_len: data_len,
                    ttl: ttl,
                })
            }
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A, // 1
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num),
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion {
            name: name,
            qtype: qtype,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class

        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {

    /// This gives us a fresh buffer for holding the packet contents, and a
    /// field for keeping track of where we are.
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    /// Current position within buffer
    fn pos(&self) -> usize {
        self.pos
    }

    /// Step the buffer position forward a specific number of steps
    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }

    /// Change the buffer position
    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    /// Read a single byte and move the position one step forward
    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Get a single byte, without changing the buffer position
    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err("End of buffer".into());
        }
        Ok(self.buf[pos])
    }

    /// Get a range of bytes
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err("End of buffer".into());
        }
        Ok(&self.buf[start..start + len as usize])
    }

    /// Read two bytes, stepping two steps forward
    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    /// Read four bytes, stepping four steps forward
    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }


    /// Read a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within the struct. This
        // allows us to move the shared position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        let mut pos = self.pos();

        // track whether or not we've jumped
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        // Our delimiter which we append for each label. Since we don't want a
        // dot at the beginning of the domain name we'll leave it empty for now
        // and set it to "." at the end of the first iteration.
        let mut delim = "";
        loop {
            // Dns Packets are untrusted data, so we need to be paranoid. Someone
            // can craft a packet with a cycle in the jump instructions. This guards
            // against such packets.
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            // At this point, we're always at the beginning of a label. Recall
            // that labels start with a length byte.
            let len = self.get(pos)?;

            // If len has the two most significant bit are set, it represents a
            // jump to some other offset in the packet:
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current
                // label. We don't need to touch it any further.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate offset and perform the jump by
                // updating our local position variable
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indicate that a jump was performed.
                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // The base scenario, where we're reading a single label and
            // appending it to the output:
            else {
                // Move a single byte forward to move past the length byte.
                pos += 1;

                // Domain names are terminated by an empty label of length 0,
                // so if the length is zero we're done.
                if len == 0 {
                    break;
                }

                // Append the delimiter to our output buffer first.
                outstr.push_str(delim);

                // Extract the actual ASCII bytes for this label and append them
                // to the output buffer.
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Move forward the full length of the label.
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}

/**
 * ```text
 * ID
 * 
 * ```
 */
#[derive(Clone, Debug)]
pub struct DnsHeader {
    /// ID | Packet Identifier | 16 bits
    pub id: u16,
    /// QR | Query Response | 1 bit
    pub response: bool,
    /// OPCODE | Operation Code | 4 bits
    pub opcode: u8,
    /// AA | Authoritative Answer | 1 bit
    pub authoritative_answer: bool,
    /// TC | Truncated Message | 1 bit
    pub truncated_message: bool,
    /// RD | Recursion Desired | 1 bit
    pub recursion_desired: bool,
    /// RA | Recursion Available | 1 bit
    pub recursion_available: bool,
    /// Z | | 1 bit
    pub z: bool,
    /// | | 1 bit
    pub authed_data: bool, 
    /// | | 1 bit
    pub checking_disabled: bool,

    /// RCODE | Response Code | 4 bits
    pub response_code: ResultCode,
    /// QDCOUNT | Question Count | 16 bits
    pub questions: u16,
    /// ANCOUNT | Answer Count | 16 bits
    pub answers: u16,
    /// NSCOUNT | Authority Count | 16 bits
    pub authoritative_entries: u16,
    /// ARCOUNT | Additional Count | 16 bits
    pub resource_entries: u16,  
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0, 
            response: false, 
            opcode: 0,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: false,

            recursion_available: false,
            z: false,
            authed_data: false,
            checking_disabled: false,
            response_code: ResultCode::NOERROR,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;
        
        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0x00FF) as u8;
        self.response = (a & (1 << 7)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.recursion_desired = (a & (1 << 0)) > 0;

        self.recursion_available = (b & (1 << 7)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.response_code = ResultCode::from_num(b & 0x0F);


        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }
}


#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }
}


fn main() -> Result<()>{
    // the query `dig NS @8.8.8.8 com`
    let mut query: Vec<u8> = vec![
        0xcc, 0xc2, 0xe0, 0x9a, 0xde, 0x28, 0x00, 0xd7, 0x6d, 0x96, 0x1b, 0x6c, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x48, 0x4d, 0x5f, 0x00, 0x00, 0x40, 0x11, 0x5b, 0x82, 0xc0, 0xa8, 0x01, 0x0c, 0x08, 0x08,
        0x08, 0x08, 0xe4, 0x71, 0x00, 0x35, 0x00, 0x34, 0xd2, 0x09, 0x5a, 0xbd, 0x01, 0x20, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
        0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0xfe, 0x2c,
        0x7b, 0x94, 0x2a, 0xd4, 0xd0, 0x5c
        ];

    let mut query_padding = vec![0; 512 - query.len()];
    query.append(&mut query_padding);
    let mut bytes = [0; 512];
    bytes.copy_from_slice(&query);

    let mut buffer = BytePacketBuffer {
        buf: bytes,
        pos: 0,
    };

    let dns_packet = DnsPacket::from_buffer(&mut buffer)?;


    dbg!(dns_packet);

    Ok(())
}
