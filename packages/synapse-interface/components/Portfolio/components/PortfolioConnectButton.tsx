import { useMemo, useState } from 'react'
import { useDispatch } from 'react-redux'
import { switchChain } from '@wagmi/core'
import { setFromChainId } from '@/slices/bridge/reducer'
import { wagmiConfig } from '@/wagmiConfig'

type PortfolioConnectButton = {
  portfolioChainId: number
  connectedChainId: number
}

export const PortfolioConnectButton = ({
  portfolioChainId,
  connectedChainId,
}: PortfolioConnectButton) => {
  const isCurrentlyConnectedNetwork: boolean = useMemo(() => {
    return portfolioChainId === connectedChainId
  }, [portfolioChainId, connectedChainId])

  return (
    <div id="portfolio-connect-button">
      {isCurrentlyConnectedNetwork ? (
        <ConnectedButton />
      ) : (
        <ConnectButton chainId={portfolioChainId} />
      )}
    </div>
  )
}

const ConnectedButton = () => {
  return (
    <button
      id="connected-button"
      className={`
        flex items-center justify-center
        text-base text-white px-3 py-1 rounded-lg
        text-center transform-gpu transition-all duration-75
        border border-solid border-transparent
        hover:border-[#3D3D5C] hover:cursor-not-allowed
      `}
    >
      <div className="flex flex-row text-sm">
        <div
          className={`
            my-auto ml-auto mr-2 w-2 h-2
            bg-green-400 rounded-full
          `}
        />
        Connected
      </div>
    </button>
  )
}

const ConnectButton = ({ chainId }: { chainId: number }) => {
  const [isConnecting, setIsConnecting] = useState<boolean>(false)
  const dispatch = useDispatch()

  function scrollToTop(): void {
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const handleConnectNetwork: () => Promise<void> = async () => {
    setIsConnecting(true)
    try {
      await switchChain(wagmiConfig, { chainId: chainId as any }).then(
        (success) => {
          success && dispatch(setFromChainId(chainId))
          scrollToTop()
        }
      )
    } catch (error) {
      error && setIsConnecting(false)
    }
  }

  return (
    <button
      id="connect-button"
      className={`
        flex items-right justify-center
        text-base text-white px-3 py-1 rounded-lg
        text-center transform-gpu transition-all duration-75
        border border-solid border-transparent
        hover:border-[#3D3D5C]
      `}
      onClick={handleConnectNetwork}
    >
      {isConnecting ? (
        <div className="flex flex-row text-sm">
          <div
            className={`
              my-auto ml-auto mr-2 text-transparent w-2 h-2
              border border-green-400 border-solid rounded-full
            `}
          />
          Connecting...
        </div>
      ) : (
        <div className="flex flex-row text-sm">
          <div
            className={`
              my-auto ml-auto mr-2 text-transparent w-2 h-2
              border border-indigo-300 border-solid rounded-full
            `}
          />
          Connect
        </div>
      )}
    </button>
  )
}
