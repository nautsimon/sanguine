import React, { useState, useEffect } from 'react'
import {
  ChevronDoubleDownIcon,
  ChevronDoubleUpIcon,
} from '@heroicons/react/outline'

type PortfolioAccordionProps = {
  header: React.ReactNode
  expandedProps: React.ReactNode
  collapsedProps: React.ReactNode
  children: React.ReactNode
  initializeExpanded: boolean
  portfolioChainId: number
  connectedChainId: number
  selectedFromChainId: number
}

export const PortfolioAccordion = ({
  header,
  expandedProps,
  collapsedProps,
  children,
  initializeExpanded = false,
  portfolioChainId,
  connectedChainId,
  selectedFromChainId,
}: PortfolioAccordionProps) => {
  const [isExpanded, setIsExpanded] = useState(false)
  const handleToggle = () => setIsExpanded((prevExpanded) => !prevExpanded)

  useEffect(() => {
    portfolioChainId === selectedFromChainId
      ? setIsExpanded(true)
      : setIsExpanded(false)
  }, [portfolioChainId, selectedFromChainId])

  return (
    <div
      data-test-id="portfolio-accordion"
      className={
        isExpanded ? 'shadow-[0px_4px_4px_0px_rgba(0,0,0,0.25)]' : 'shadow-none'
      }
    >
      <div
        data-test-id="portfolio-accordion-header"
        className={`
          flex items-center justify-between border border-transparent pr-2 select-none
          hover:border-[#3D3D5C] hover:bg-[#272731]
          active:border-[#3D3D5C] active:opacity-[67%]
          ${
            isExpanded
              ? 'bg-tint rounded-t-md hover:rounded-t-md'
              : 'bg-transparent rounded-md'
          }
        `}
      >
        <div onClick={handleToggle} className="flex-1 mr-3">
          <div
            data-test-id="portfolio-accordion-clickable"
            className="flex flex-row justify-between"
          >
            {header}
            {!isExpanded && collapsedProps}
          </div>
        </div>
        {isExpanded && expandedProps}
        <AccordionIcon isExpanded={isExpanded} onClick={handleToggle} />
      </div>
      <div
        data-test-id="portfolio-accordion-contents"
        className="flex flex-col"
      >
        {isExpanded && <React.Fragment>{children}</React.Fragment>}
      </div>
    </div>
  )
}

export const AccordionIcon = ({
  isExpanded,
  onClick,
}: {
  isExpanded: boolean
  onClick: () => void
}) => {
  return (
    <div
      data-test-id="accordion-icon"
      onClick={onClick}
      className={`
        p-1 mx-2 border border-surface rounded-full
        cursor-pointer hover:border-transparent active:border-transparent
      `}
    >
      {isExpanded ? (
        <ChevronDoubleUpIcon className="w-4 h-4 stroke-[3] stroke-separator" />
      ) : (
        <ChevronDoubleDownIcon className="w-4 h-4 stroke-[3] stroke-separator" />
      )}
    </div>
  )
}
