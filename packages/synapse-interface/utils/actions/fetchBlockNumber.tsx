import { fetchBlockNumber } from '@wagmi/core'
import { BRIDGABLE_TOKENS } from '@/constants/tokens'

export const getCurrentBlockNumber = async (
  chainId: number
): Promise<bigint> => {
  try {
    const blockNumber = await fetchBlockNumber({
      chainId: chainId,
    })
    return blockNumber
  } catch (error) {
    console.error('getCurrentBlockNumber: ', error)
  }
}

export const getChainsBlockNumber = async () => {
  const record = {}
  const availableChains: string[] = Object.keys(BRIDGABLE_TOKENS)

  const filteredChains: string[] = availableChains.filter((chain: string) => {
    return chain !== '2000' // exclude Dogechain
  })

  try {
    const getBlockNumberPromises = filteredChains.map(
      async (chainId: string) => {
        const currentChainId = Number(chainId)
        const currentBlockNumber = await getCurrentBlockNumber(currentChainId)
        return currentBlockNumber
      }
    )

    const blockNumbers = await Promise.all(getBlockNumberPromises)
    blockNumbers.forEach((blockNumber: bigint, index: number) => {
      record[filteredChains[index]] = Number(blockNumber.toString())
    })
    return record
  } catch (error) {
    console.error('Error from getChainsBlockNumber: ', error)
  }
}
