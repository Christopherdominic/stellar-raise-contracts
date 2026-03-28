/**
 * @file frontend_header_responsive.test.tsx
 * @title Test Suite - FrontendHeaderResponsive (Edge Cases for Smart Contract)
 * @notice Comprehensive unit tests covering smart-contract-specific edge cases:
 *   wallet address truncation, network validation, transaction pending state,
 *   and wallet connecting state.
 * @custom:security-notes
 *   - Stale-closure test confirms callback always receives new state value.
 *   - Network allowlist test confirms arbitrary strings are not rendered.
 *   - Address truncation test confirms full keys are never displayed verbatim.
 */

import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import {
  FrontendHeaderResponsive,
  truncateWalletAddress,
  resolveNetworkLabel,
  SUPPORTED_NETWORKS,
} from './frontend_header_responsive';

const VALID_ADDRESS = 'G' + 'A'.repeat(55);
const VALID_ADDRESS_2 = 'G' + 'B'.repeat(51) + 'ZZZZ';
const SHORT_ADDRESS = 'GABC1234';
const LONG_ADDRESS = 'G' + 'A'.repeat(60);

const renderHeader = (props = {}) =>
  render(<FrontendHeaderResponsive isWalletConnected={false} {...props} />);

const getToggleBtn = () =>
  screen.getByRole('button', { name: /toggle navigation menu/i });

describe('1. Rendering', () => {
  it('1.1 renders the brand logo text', () => {
    renderHeader();
    expect(screen.getByText('Stellar Raise')).toBeTruthy();
  });
  it('1.2 renders all three default navigation links', () => {
    renderHeader();
    expect(screen.getByText('Dashboard')).toBeTruthy();
    expect(screen.getByText('Invest')).toBeTruthy();
    expect(screen.getByText('Docs')).toBeTruthy();
  });
  it('1.3 renders the mobile menu toggle button', () => {
    renderHeader();
    expect(getToggleBtn()).toBeTruthy();
  });
  it('1.4 nav links have correct hrefs', () => {
    renderHeader();
    expect(screen.getByRole('link', { name: 'Dashboard' })).toHaveAttribute('href', '/dashboard');
    expect(screen.getByRole('link', { name: 'Invest' })).toHaveAttribute('href', '/invest');
    expect(screen.getByRole('link', { name: 'Docs' })).toHaveAttribute('href', '/docs');
  });
  it('1.5 renders without error with only required prop', () => {
    expect(() => render(<FrontendHeaderResponsive isWalletConnected={false} />)).not.toThrow();
  });
  it('1.6 renders without error with all props', () => {
    expect(() =>
      render(<FrontendHeaderResponsive isWalletConnected={true} onToggleMenu={jest.fn()} walletAddress={VALID_ADDRESS} networkName="testnet" isTransactionPending={false} isWalletConnecting={false} />)
    ).not.toThrow();
  });
});

describe('2. Wallet Status Badge - Basic States', () => {
  it('2.1 shows Disconnected when isWalletConnected is false', () => {
    renderHeader({ isWalletConnected: false });
    expect(screen.getByText('Disconnected')).toBeTruthy();
  });
  it('2.2 shows Connected when isWalletConnected is true', () => {
    renderHeader({ isWalletConnected: true });
    expect(screen.getByText('Connected')).toBeTruthy();
  });
  it('2.3 applies red border when disconnected', () => {
    renderHeader({ isWalletConnected: false });
    expect(screen.getByText('Disconnected').closest('.wallet-status')).toHaveStyle({ border: '1px solid #FF3B30' });
  });
  it('2.4 applies green border when connected', () => {
    renderHeader({ isWalletConnected: true });
    expect(screen.getByText('Connected').closest('.wallet-status')).toHaveStyle({ border: '1px solid #00C853' });
  });
  it('2.5 applies red background tint when disconnected', () => {
    renderHeader({ isWalletConnected: false });
    expect(screen.getByText('Disconnected').closest('.wallet-status')).toHaveStyle({ backgroundColor: 'rgba(255, 59, 48, 0.1)' });
  });
  it('2.6 applies green background tint when connected', () => {
    renderHeader({ isWalletConnected: true });
    expect(screen.getByText('Connected').closest('.wallet-status')).toHaveStyle({ backgroundColor: 'rgba(0, 200, 83, 0.1)' });
  });
});

describe('3. Mobile Menu Toggle - State', () => {
  it('3.1 menu starts closed', () => {
    renderHeader();
    expect(getToggleBtn()).toHaveAttribute('aria-expanded', 'false');
  });
  it('3.2 shows hamburger icon when closed', () => {
    renderHeader();
    expect(getToggleBtn()).toHaveTextContent('☰');
  });
  it('3.3 clicking toggle opens the menu', () => {
    renderHeader();
    fireEvent.click(getToggleBtn());
    expect(getToggleBtn()).toHaveAttribute('aria-expanded', 'true');
  });
  it('3.4 shows close icon when open', () => {
    renderHeader();
    fireEvent.click(getToggleBtn());
    expect(getToggleBtn()).toHaveTextContent('✖');
  });
  it('3.5 clicking toggle again closes the menu', () => {
    renderHeader();
    fireEvent.click(getToggleBtn());
    fireEvent.click(getToggleBtn());
    expect(getToggleBtn()).toHaveAttribute('aria-expanded', 'false');
  });
  it('3.6 hamburger icon restored after close', () => {
    renderHeader();
    fireEvent.click(getToggleBtn());
    fireEvent.click(getToggleBtn());
    expect(getToggleBtn()).toHaveTextContent('☰');
  });
  it('3.7 nav acquires block class when open', () => {
    renderHeader();
    fireEvent.click(getToggleBtn());
    expect(document.querySelector('.nav-links')?.className).toContain('block');
  });
  it('3.8 nav acquires hidden class when closed', () => {
    renderHeader();
    expect(document.querySelector('.nav-links')?.className).toContain('hidden');
  });
});

describe('4. onToggleMenu Callback', () => {
  it('4.1 fires with true when opened', () => {
    const spy = jest.fn();
    renderHeader({ onToggleMenu: spy });
    fireEvent.click(getToggleBtn());
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(true);
  });
  it('4.2 fires with false when closed', () => {
    const spy = jest.fn();
    renderHeader({ onToggleMenu: spy });
    fireEvent.click(getToggleBtn());
    fireEvent.click(getToggleBtn());
    expect(spy).toHaveBeenCalledTimes(2);
    expect(spy).toHaveBeenNthCalledWith(2, false);
  });
  it('4.3 does not throw without callback', () => {
    expect(() => { renderHeader(); fireEvent.click(getToggleBtn()); }).not.toThrow();
  });
  it('4.4 callback always receives NEW state (stale-closure safety)', () => {
    const received: boolean[] = [];
    renderHeader({ onToggleMenu: (v: boolean) => received.push(v) });
    fireEvent.click(getToggleBtn());
    fireEvent.click(getToggleBtn());
    fireEvent.click(getToggleBtn());
    expect(received).toEqual([true, false, true]);
  });
  it('4.5 callback not called on initial render', () => {
    const spy = jest.fn();
    renderHeader({ onToggleMenu: spy });
    expect(spy).not.toHaveBeenCalled();
  });
});

describe('5. Accessibility Attributes', () => {
  it('5.1 toggle button has correct aria-label', () => {
    renderHeader();
    expect(getToggleBtn()).toHaveAttribute('aria-label', 'Toggle Navigation Menu');
  });
  it('5.2 aria-expanded is false initially', () => {
    renderHeader();
    expect(getToggleBtn()).toHaveAttribute('aria-expanded', 'false');
  });
  it('5.3 aria-expanded is true after click', () => {
    renderHeader();
    fireEvent.click(getToggleBtn());
    expect(getToggleBtn()).toHaveAttribute('aria-expanded', 'true');
  });
  it('5.4 wallet badge aria-busy is false when no transaction pending', () => {
    renderHeader({ isWalletConnected: true });
    expect(screen.getByText('Connected').closest('.wallet-status')).toHaveAttribute('aria-busy', 'false');
  });
  it('5.5 wallet badge aria-busy is true when transaction pending', () => {
    renderHeader({ isWalletConnected: true, isTransactionPending: true });
    expect(screen.getByText('Pending…').closest('.wallet-status')).toHaveAttribute('aria-busy', 'true');
  });
  it('5.6 wallet badge has descriptive aria-label', () => {
    renderHeader({ isWalletConnected: true });
    expect(screen.getByText('Connected').closest('.wallet-status')).toHaveAttribute('aria-label', 'Wallet status: Connected');
  });
});

describe('6. Edge Cases - Rapid Toggles', () => {
  it('6.1 three rapid toggles leaves menu open', () => {
    renderHeader();
    fireEvent.click(getToggleBtn());
    fireEvent.click(getToggleBtn());
    fireEvent.click(getToggleBtn());
    expect(getToggleBtn()).toHaveAttribute('aria-expanded', 'true');
  });
  it('6.2 four rapid toggles leaves menu closed', () => {
    renderHeader();
    fireEvent.click(getToggleBtn());
    fireEvent.click(getToggleBtn());
    fireEvent.click(getToggleBtn());
    fireEvent.click(getToggleBtn());
    expect(getToggleBtn()).toHaveAttribute('aria-expanded', 'false');
  });
});

describe('7. Edge Cases - Wallet Address Truncation', () => {
  it('7.1 shows truncated address when connected with valid address', () => {
    renderHeader({ isWalletConnected: true, walletAddress: VALID_ADDRESS });
    expect(screen.getByText('G...AAAA')).toBeTruthy();
  });
  it('7.2 shows correct tail for different valid address', () => {
    renderHeader({ isWalletConnected: true, walletAddress: VALID_ADDRESS_2 });
    expect(screen.getByText('G...ZZZZ')).toBeTruthy();
  });
  it('7.3 does NOT show address when disconnected', () => {
    renderHeader({ isWalletConnected: false, walletAddress: VALID_ADDRESS });
    expect(screen.queryByText('G...AAAA')).toBeNull();
  });
  it('7.4 does NOT show address when address is too short', () => {
    renderHeader({ isWalletConnected: true, walletAddress: SHORT_ADDRESS });
    expect(screen.queryByText(/G\.\.\./)).toBeNull();
  });
  it('7.5 does NOT show address when address is too long', () => {
    renderHeader({ isWalletConnected: true, walletAddress: LONG_ADDRESS });
    expect(screen.queryByText(/G\.\.\./)).toBeNull();
  });
  it('7.6 does NOT show address when walletAddress omitted', () => {
    renderHeader({ isWalletConnected: true });
    expect(screen.queryByText(/G\.\.\./)).toBeNull();
  });
  it('7.7 does NOT show address while transaction pending', () => {
    renderHeader({ isWalletConnected: true, walletAddress: VALID_ADDRESS, isTransactionPending: true });
    expect(screen.queryByText('G...AAAA')).toBeNull();
  });
  it('7.8 does NOT show address while wallet connecting', () => {
    renderHeader({ isWalletConnected: false, walletAddress: VALID_ADDRESS, isWalletConnecting: true });
    expect(screen.queryByText('G...AAAA')).toBeNull();
  });
});

describe('8. Edge Cases - Network Label Validation', () => {
  it('8.1 shows testnet label', () => {
    renderHeader({ isWalletConnected: true, networkName: 'testnet' });
    expect(screen.getByText('testnet')).toBeTruthy();
  });
  it('8.2 shows mainnet label', () => {
    renderHeader({ isWalletConnected: true, networkName: 'mainnet' });
    expect(screen.getByText('mainnet')).toBeTruthy();
  });
  it('8.3 shows futurenet label', () => {
    renderHeader({ isWalletConnected: true, networkName: 'futurenet' });
    expect(screen.getByText('futurenet')).toBeTruthy();
  });
  it('8.4 shows localnet label', () => {
    renderHeader({ isWalletConnected: true, networkName: 'localnet' });
    expect(screen.getByText('localnet')).toBeTruthy();
  });
  it('8.5 shows Unknown Network for unrecognised network', () => {
    renderHeader({ isWalletConnected: true, networkName: 'devnet' });
    expect(screen.getByText('Unknown Network')).toBeTruthy();
  });
  it('8.6 shows Unknown Network for injection-attempt string', () => {
    renderHeader({ isWalletConnected: true, networkName: '<script>alert(1)</script>' });
    expect(screen.getByText('Unknown Network')).toBeTruthy();
    expect(screen.queryByText('<script>alert(1)</script>')).toBeNull();
  });
  it('8.7 does NOT show network label when omitted', () => {
    renderHeader({ isWalletConnected: true });
    expect(screen.queryByText('testnet')).toBeNull();
  });
  it('8.8 does NOT show network label when disconnected', () => {
    renderHeader({ isWalletConnected: false, networkName: 'testnet' });
    expect(screen.queryByText('testnet')).toBeNull();
  });
  it('8.9 does NOT show network label while pending', () => {
    renderHeader({ isWalletConnected: true, networkName: 'testnet', isTransactionPending: true });
    expect(screen.queryByText('testnet')).toBeNull();
  });
});

describe('9. Edge Cases - Transaction Pending State', () => {
  it('9.1 shows Pending badge when isTransactionPending is true', () => {
    renderHeader({ isWalletConnected: true, isTransactionPending: true });
    expect(screen.getByText('Pending…')).toBeTruthy();
  });
  it('9.2 pending overrides connected state', () => {
    renderHeader({ isWalletConnected: true, isTransactionPending: true });
    expect(screen.queryByText('Connected')).toBeNull();
    expect(screen.getByText('Pending…')).toBeTruthy();
  });
  it('9.3 pending overrides disconnected state', () => {
    renderHeader({ isWalletConnected: false, isTransactionPending: true });
    expect(screen.queryByText('Disconnected')).toBeNull();
    expect(screen.getByText('Pending…')).toBeTruthy();
  });
  it('9.4 applies orange border when pending', () => {
    renderHeader({ isWalletConnected: true, isTransactionPending: true });
    expect(screen.getByText('Pending…').closest('.wallet-status')).toHaveStyle({ border: '1px solid #FF9500' });
  });
  it('9.5 applies orange background tint when pending', () => {
    renderHeader({ isWalletConnected: true, isTransactionPending: true });
    expect(screen.getByText('Pending…').closest('.wallet-status')).toHaveStyle({ backgroundColor: 'rgba(255, 149, 0, 0.1)' });
  });
  it('9.6 shows Connected when isTransactionPending is false', () => {
    renderHeader({ isWalletConnected: true, isTransactionPending: false });
    expect(screen.getByText('Connected')).toBeTruthy();
  });
  it('9.7 pending defaults to false when omitted', () => {
    renderHeader({ isWalletConnected: true });
    expect(screen.queryByText('Pending…')).toBeNull();
    expect(screen.getByText('Connected')).toBeTruthy();
  });
});

describe('10. Edge Cases - Wallet Connecting State', () => {
  it('10.1 shows Connecting badge when isWalletConnecting is true', () => {
    renderHeader({ isWalletConnected: false, isWalletConnecting: true });
    expect(screen.getByText('Connecting…')).toBeTruthy();
  });
  it('10.2 connecting overrides disconnected state', () => {
    renderHeader({ isWalletConnected: false, isWalletConnecting: true });
    expect(screen.queryByText('Disconnected')).toBeNull();
    expect(screen.getByText('Connecting…')).toBeTruthy();
  });
  it('10.3 pending overrides connecting state', () => {
    renderHeader({ isWalletConnected: false, isWalletConnecting: true, isTransactionPending: true });
    expect(screen.queryByText('Connecting…')).toBeNull();
    expect(screen.getByText('Pending…')).toBeTruthy();
  });
  it('10.4 applies blue border when connecting', () => {
    renderHeader({ isWalletConnected: false, isWalletConnecting: true });
    expect(screen.getByText('Connecting…').closest('.wallet-status')).toHaveStyle({ border: '1px solid #0066FF' });
  });
  it('10.5 applies blue background tint when connecting', () => {
    renderHeader({ isWalletConnected: false, isWalletConnecting: true });
    expect(screen.getByText('Connecting…').closest('.wallet-status')).toHaveStyle({ backgroundColor: 'rgba(0, 102, 255, 0.1)' });
  });
  it('10.6 connecting defaults to false when omitted', () => {
    renderHeader({ isWalletConnected: false });
    expect(screen.queryByText('Connecting…')).toBeNull();
    expect(screen.getByText('Disconnected')).toBeTruthy();
  });
});

describe('11. truncateWalletAddress', () => {
  it('11.1 returns truncated form for valid 56-char address', () => {
    expect(truncateWalletAddress(VALID_ADDRESS)).toBe('G...AAAA');
  });
  it('11.2 uses last 4 chars as tail', () => {
    expect(truncateWalletAddress(VALID_ADDRESS_2)).toBe('G...ZZZZ');
  });
  it('11.3 returns null for address shorter than 56 chars', () => {
    expect(truncateWalletAddress(SHORT_ADDRESS)).toBeNull();
  });
  it('11.4 returns null for address longer than 56 chars', () => {
    expect(truncateWalletAddress(LONG_ADDRESS)).toBeNull();
  });
  it('11.5 returns null for empty string', () => {
    expect(truncateWalletAddress('')).toBeNull();
  });
  it('11.6 returns null for undefined', () => {
    expect(truncateWalletAddress(undefined)).toBeNull();
  });
  it('11.7 returns null for 55-char address', () => {
    expect(truncateWalletAddress('G' + 'A'.repeat(54))).toBeNull();
  });
  it('11.8 returns null for 57-char address', () => {
    expect(truncateWalletAddress('G' + 'A'.repeat(56))).toBeNull();
  });
});

describe('12. resolveNetworkLabel', () => {
  it('12.1 returns mainnet for mainnet', () => {
    expect(resolveNetworkLabel('mainnet')).toBe('mainnet');
  });
  it('12.2 returns testnet for testnet', () => {
    expect(resolveNetworkLabel('testnet')).toBe('testnet');
  });
  it('12.3 returns futurenet for futurenet', () => {
    expect(resolveNetworkLabel('futurenet')).toBe('futurenet');
  });
  it('12.4 returns localnet for localnet', () => {
    expect(resolveNetworkLabel('localnet')).toBe('localnet');
  });
  it('12.5 returns Unknown Network for unrecognised string', () => {
    expect(resolveNetworkLabel('devnet')).toBe('Unknown Network');
  });
  it('12.6 returns null for empty string', () => {
    expect(resolveNetworkLabel('')).toBeNull();
  });
  it('12.7 returns null for undefined', () => {
    expect(resolveNetworkLabel(undefined)).toBeNull();
  });
  it('12.8 returns Unknown Network for injection-attempt string', () => {
    expect(resolveNetworkLabel('<script>alert(1)</script>')).toBe('Unknown Network');
  });
  it('12.9 SUPPORTED_NETWORKS has exactly four values', () => {
    expect(SUPPORTED_NETWORKS).toContain('mainnet');
    expect(SUPPORTED_NETWORKS).toContain('testnet');
    expect(SUPPORTED_NETWORKS).toContain('futurenet');
    expect(SUPPORTED_NETWORKS).toContain('localnet');
    expect(SUPPORTED_NETWORKS).toHaveLength(4);
  });
});
