import { SrvRecord } from 'dns'
import { Resolver, resolveSrv } from 'dns/promises'
import { connect } from 'net'
import { LoggerUtil } from '../../util/LoggerUtil'
import { ServerBoundPacket, ClientBoundPacket, ProtocolUtils } from './Protocol'

const logger = LoggerUtil.getLogger('ServerStatusUtil')

export interface ServerStatus {
    version: {
        name: string
        protocol: number
    }
    players: {
        max: number
        online: number
        sample: {
            name: string
            id: string
        }[]
    }
    description: {
        text: string
    }
    favicon: string
    modinfo?: {             // Only for modded servers
        type: string        // Ex. FML
        modList: {
            modid: string
            version: string
        }[]
    }
    retrievedAt: number     // Internal tracking
}

/**
 * Get the handshake packet.
 * 
 * @param protocol The client's protocol version.
 * @param hostname The server hostname.
 * @param port The server port.
 * 
 * @see https://wiki.vg/Server_List_Ping#Handshake
 */
function getHandshakePacket(protocol: number, hostname: string, port: number): Buffer {

    return ServerBoundPacket.build()
        .writeVarInt(0x00)         // Packet Id 
        .writeVarInt(protocol)
        .writeString(hostname)
        .writeUnsignedShort(port)
        .writeVarInt(1)            // State, 1 = status
        .toBuffer()
}

/**
 * Get the request packet.
 * 
 * @see https://wiki.vg/Server_List_Ping#Request
 */
function getRequestPacket(): Buffer {

    return ServerBoundPacket.build()
        .writeVarInt(0x00)
        .toBuffer()
}

/**
 * Some servers do not return the same status object. Unify
 * the response so that the caller need only worry about
 * handling a single format.
 * 
 * @param resp The servevr status response.
 */
function unifyStatusResponse(resp: ServerStatus): ServerStatus {
    // Some servers don't wrap their description in a text object.
    if(typeof resp.description === 'string') {
        resp.description = {
            text: resp.description
        }
    }
    resp.retrievedAt = (new Date()).getTime()
    return resp
}

const SRV_RESOLVER_FAILURE_CODES = new Set([
    'ECONNREFUSED',
    'ECONNRESET',
    'ETIMEOUT',
    'ETIMEDOUT'
])

async function checkSrv(hostname: string): Promise<SrvRecord | null> {
    const query = `_minecraft._tcp.${hostname}`
    try {
        const records = await resolveSrv(query)
        return records.length > 0 ? records[0] : null
    } catch(err) {
        const code = (err as NodeJS.ErrnoException).code
        // Retry public resolvers only when the local resolver appears unreachable.
        // DNS response codes such as ESERVFAIL/EREFUSED are treated as valid resolver
        // outcomes (including policy responses) and should not trigger a bypass.
        if (code == null || !SRV_RESOLVER_FAILURE_CODES.has(code)) {
            return null
        }
        logger.warn(`System SRV lookup failed with ${code}, retrying via public resolver.`)
        try {
            const resolver = new Resolver()
            resolver.setServers(['1.1.1.1', '8.8.8.8'])
            const records = await resolver.resolveSrv(query)
            return records.length > 0 ? records[0] : null
        } catch {
            return null
        }
    }
}

export async function getServerStatus(protocol: number, hostname: string, port = 25565): Promise<ServerStatus> {

    const srvRecord = await checkSrv(hostname)
    if(srvRecord != null) {
        hostname = srvRecord.name
        port = srvRecord.port
    }

    return await new Promise((resolve, reject) => {

        const socket = connect(port, hostname, () => {
            socket.write(getHandshakePacket(protocol, hostname, port))
            socket.write(getRequestPacket())
        })

        socket.setTimeout(5000, () => {
            socket.destroy()
            logger.error(`Server Status Socket timed out (${hostname}:${port})`)
            reject(new Error(`Server Status Socket timed out (${hostname}:${port})`))
        })

        const maxTries = 5
        let iterations = 0
        let bytesLeft = -1

        socket.once('data', (data) => {

            const inboundPacket = new ClientBoundPacket(data)
            
            // Length of Packet ID + Data
            const packetLength = inboundPacket.readVarInt() // First VarInt is packet length.
            const packetType = inboundPacket.readVarInt()   // Second VarInt is packet type.

            if(packetType !== 0x00) {
                // TODO
                socket.destroy()
                reject(new Error(`Invalid response. Expected packet type ${0x00}, received ${packetType}!`))
                return
            }

            // Size of packetLength VarInt is not included in the packetLength.
            bytesLeft = packetLength + ProtocolUtils.getVarIntSize(packetLength)

            // Listener to keep reading until we have read all the bytes into the buffer.
            const packetReadListener = (nextData: Buffer, doAppend: boolean): void => {

                if(iterations > maxTries) {
                    socket.destroy()
                    reject(new Error(`Data read from ${hostname}:${port} exceeded ${maxTries} iterations, closing connection.`))
                    return
                }
                ++iterations

                if(bytesLeft > 0) {
                    bytesLeft -= nextData.length
                    if(doAppend) {
                        inboundPacket.append(nextData)
                    }
                }

                // All bytes read, attempt conversion.
                if(bytesLeft === 0) {
            
                    // Remainder of Buffer is the server status json.
                    const result = inboundPacket.readString()

                    try {
                        const parsed = JSON.parse(result) as ServerStatus
                        socket.end()
                        resolve(unifyStatusResponse(parsed))
                    } catch(err) {
                        socket.destroy()
                        logger.error('Failed to parse server status JSON', err)
                        reject(new Error('Failed to parse server status JSON'))
                    }
                }
            }

            // Read the data we just received.
            packetReadListener(data, false)
            // Add a listener to keep reading if the data is too long.
            socket.on('data', (data) => packetReadListener(data, true))

        })

        socket.on('error', (err: NodeJS.ErrnoException) => {
            socket.destroy()

            if(err.code === 'ENOTFOUND') {
                // ENOTFOUND = Unable to resolve.
                reject(new Error(`Server ${hostname}:${port} not found!`))
                return
            } else if(err.code === 'ECONNREFUSED') {
                // ECONNREFUSED = Unable to connect to port.
                reject(new Error(`Server ${hostname}:${port} refused to connect, is the port correct?`))
                return
            } else {
                logger.error(`Error trying to pull server status (${hostname}:${port})`)
                reject(err)
                return
            }
        })

    })

}
