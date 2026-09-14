#include <Misc/Incl.h>
#include "Splash.h"

namespace Splash
{
    static constexpr int  Width       = 700;
    static constexpr int  Height      = 400;
    static constexpr int  BarH        = 6;
    static constexpr int  CloseSz     = 20;
    static constexpr UINT WM_PROGRESS = WM_APP + 1;
    static constexpr UINT WM_QUIT_REQ = WM_APP + 2;
    static constexpr UINT WM_ERROR    = WM_APP + 3;

    static HWND    Hwnd     = nullptr;
    static int     Progress = 0;
    static bool    InError  = false;
    static wchar_t ErrMsg[256] = {};

    // Close button rect (client coords), positioned above the bar in the bottom-right corner
    //
    static constexpr RECT CloseRc = {
        Width  - CloseSz - 4,
        Height - BarH - CloseSz - 4,
        Width  - 4,
        Height - BarH - 4
    };

    static LRESULT CALLBACK WndProc( HWND Wnd, UINT Msg, WPARAM Wp, LPARAM Lp )
    {
        switch ( Msg )
        {
        case WM_ERASEBKGND:
            return 1;

        case WM_PROGRESS:
            Progress = static_cast< int >( Wp );
            InvalidateRect( Wnd, nullptr, FALSE );
            return 0;

        case WM_QUIT_REQ:
            DestroyWindow( Wnd );
            return 0;

        case WM_ERROR:
            InError = true;
            wcscpy_s( ErrMsg, reinterpret_cast< const wchar_t* >( Wp ) );
            InvalidateRect( Wnd, nullptr, FALSE );
            return 0;

        case WM_LBUTTONDOWN:
        {
            int Mx = static_cast< int >( LOWORD( Lp ) );
            int My = static_cast< int >( HIWORD( Lp ) );
            if ( Mx >= CloseRc.left && Mx < CloseRc.right &&
                 My >= CloseRc.top  && My < CloseRc.bottom )
                DestroyWindow( Wnd );
            return 0;
        }

        case WM_KEYDOWN:
            if ( InError && Wp == VK_ESCAPE )
                DestroyWindow( Wnd );
            return 0;

        case WM_PAINT:
        {
            PAINTSTRUCT Ps;
            HDC Dc = BeginPaint( Wnd, &Ps );

            RECT Rc;
            GetClientRect( Wnd, &Rc );

            // Double-buffer to suppress flicker
            //
            HDC     MemDc  = CreateCompatibleDC( Dc );
            HBITMAP Bmp    = CreateCompatibleBitmap( Dc, Rc.right, Rc.bottom );
            HGDIOBJ OldBmp = SelectObject( MemDc, Bmp );

            HBRUSH Black = CreateSolidBrush( RGB( 0, 0, 0 ) );
            FillRect( MemDc, &Rc, Black );
            DeleteObject( Black );

            SetBkMode( MemDc, TRANSPARENT );

            // Error message text, centered above the bar
            //
            if ( InError )
            {
                HFONT Font = CreateFontW( 22, 0, 0, 0, FW_NORMAL,
                    FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                    OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                    CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI" );
                HGDIOBJ OldFont = SelectObject( MemDc, Font );

                SetTextColor( MemDc, RGB( 220, 55, 55 ) );
                RECT TextRc = { 24, 0, Rc.right - 24, Rc.bottom - BarH };
                DrawTextW( MemDc, ErrMsg, -1, &TextRc, DT_CENTER | DT_VCENTER | DT_SINGLELINE );

                SelectObject( MemDc, OldFont );
                DeleteObject( Font );
            }

            // Progress bar: cyan while loading, full-width red on error
            //
            {
                RECT Bar;
                COLORREF BarColor;

                if ( InError )
                {
                    Bar      = { 0, Rc.bottom - BarH, Rc.right, Rc.bottom };
                    BarColor = RGB( 200, 40, 40 );
                }
                else
                {
                    int BarW = ( Rc.right * Progress ) / 100;
                    Bar      = { 0, Rc.bottom - BarH, BarW, Rc.bottom };
                    BarColor = RGB( 0, 255, 255 );
                }

                if ( Bar.right > Bar.left )
                {
                    HBRUSH BarBrush = CreateSolidBrush( BarColor );
                    FillRect( MemDc, &Bar, BarBrush );
                    DeleteObject( BarBrush );
                }
            }

            // X close button, above bar in bottom-right
            //
            {
                HFONT Font = CreateFontW( 16, 0, 0, 0, FW_NORMAL,
                    FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                    OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                    CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI" );
                HGDIOBJ OldFont = SelectObject( MemDc, Font );

                SetTextColor( MemDc, InError ? RGB( 180, 180, 180 ) : RGB( 55, 55, 55 ) );
                RECT Btn = CloseRc;
                DrawTextW( MemDc, L"×", -1, &Btn, DT_CENTER | DT_VCENTER | DT_SINGLELINE );

                SelectObject( MemDc, OldFont );
                DeleteObject( Font );
            }

            BitBlt( Dc, 0, 0, Rc.right, Rc.bottom, MemDc, 0, 0, SRCCOPY );
            SelectObject( MemDc, OldBmp );
            DeleteObject( Bmp );
            DeleteDC( MemDc );

            EndPaint( Wnd, &Ps );
            return 0;
        }

        case WM_DESTROY:
            PostQuitMessage( 0 );
            return 0;
        }

        return DefWindowProcW( Wnd, Msg, Wp, Lp );
    }

    bool Create( )
    {
        WNDCLASSEXW Wc{};
        Wc.cbSize        = sizeof( Wc );
        Wc.lpfnWndProc   = WndProc;
        Wc.hInstance     = GetModuleHandleW( nullptr );
        Wc.lpszClassName = L"ACSplash";

        if ( !RegisterClassExW( &Wc ) )
            return false;

        int X = ( GetSystemMetrics( SM_CXSCREEN ) - Width  ) / 2;
        int Y = ( GetSystemMetrics( SM_CYSCREEN ) - Height ) / 2;

        Hwnd = CreateWindowExW(
            WS_EX_TOOLWINDOW,
            L"ACSplash", nullptr,
            WS_POPUP | WS_VISIBLE,
            X, Y, Width, Height,
            nullptr, nullptr, GetModuleHandleW( nullptr ), nullptr
        );

        return Hwnd != nullptr;
    }

    void SetProgress( int Percent )
    {
        if ( Hwnd )
            PostMessageW( Hwnd, WM_PROGRESS, static_cast< WPARAM >( Percent ), 0 );
    }

    void SetError( const wchar_t* Msg )
    {
        // Msg must point to static/rodata storage that outlasts the message dispatch
        //
        if ( Hwnd )
            PostMessageW( Hwnd, WM_ERROR, reinterpret_cast< WPARAM >( Msg ), 0 );
    }

    void Quit( )
    {
        if ( Hwnd )
            PostMessageW( Hwnd, WM_QUIT_REQ, 0, 0 );
    }

    void Pump( )
    {
        MSG Msg;
        while ( GetMessageW( &Msg, nullptr, 0, 0 ) > 0 )
        {
            TranslateMessage( &Msg );
            DispatchMessageW( &Msg );
        }
    }

    void Destroy( )
    {
        if ( Hwnd )
        {
            DestroyWindow( Hwnd );
            Hwnd = nullptr;
        }
    }
}
