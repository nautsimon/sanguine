import '@/styles/global.css'
import '@rainbow-me/rainbowkit/styles.css'
import type { AppProps } from 'next/app'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

import { PersistGate } from 'redux-persist/integration/react'

import { RainbowKitProvider } from '@rainbow-me/rainbowkit'
import { Provider } from 'react-redux'
import { store, persistor } from '@/store/store'
import { SegmentAnalyticsProvider } from '@/contexts/SegmentAnalyticsProvider'
import { UserProvider } from '@/contexts/UserProvider'
import { BackgroundListenerProvider } from '@/contexts/BackgroundListenerProvider'
import CustomToaster from '@/components/toast'
import Head from 'next/head'
import { WagmiProvider } from 'wagmi'
import { SynapseProvider } from '@/utils/providers/SynapseProvider'

import LogRocket from 'logrocket'
import setupLogRocketReact from 'logrocket-react'
import { supportedChains, wagmiConfig } from '@/wagmiConfig'

// only initialize when in the browser
if (
  typeof window !== 'undefined' &&
  !location.hostname.match('synapseprotocol.com')
) {
  LogRocket.init('npdhrc/synapse-staging', {
    mergeIframes: true,
  })
  // plugins should also only be initialized when in the browser
  setupLogRocketReact(LogRocket)

  LogRocket.getSessionURL((sessionURL) => {
    console.log('session url for debugging ' + sessionURL)
  })
}

const queryClient = new QueryClient()

function App({ Component, pageProps }: AppProps) {
  return (
    <>
      <Head>
        <title>Synapse Protocol</title>
      </Head>
      <WagmiProvider config={wagmiConfig}>
        <QueryClientProvider client={queryClient}>
          <RainbowKitProvider>
            <SynapseProvider chains={supportedChains}>
              <Provider store={store}>
                <PersistGate loading={null} persistor={persistor}>
                  <SegmentAnalyticsProvider>
                    <UserProvider>
                      <BackgroundListenerProvider>
                        <Component {...pageProps} />
                      </BackgroundListenerProvider>
                      <CustomToaster />
                    </UserProvider>
                  </SegmentAnalyticsProvider>
                </PersistGate>
              </Provider>
            </SynapseProvider>
          </RainbowKitProvider>
        </QueryClientProvider>
      </WagmiProvider>
    </>
  )
}

export default App
