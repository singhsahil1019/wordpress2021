<?php 
/**
 * Common css for all devices
 *
 * @since 1.0.0
 * @package Bizline WordPress Theme
 */

add_action( 'init', 'bizline_custom_width', 99 );
add_action( 'customize_preview_init', 'bizline_custom_width', 150 );

/**
 * Adjust custom width
 *
 * @since 1.0.0
 * @package Bizline WordPress Theme
 */
function bizline_custom_width(){

	if( 'default' == bizline_get( 'container-width' ) ) :
		# container width
		$style = array(
			array(
				'selector' => '.container',
				'props' => array(
					'max-width' => 'container-custom-width',
			)
		));

		Bizline_Css::add_styles( $style, 'md' );
	endif;

}

add_action( 'init', 'bizline_all_device_css' );
/**
 * Register dynamic css
 *
 * @since 1.0.0
 * @package Bizline WordPress Theme
 */
function bizline_all_device_css(){

	$style = array(
		# Primary Color
		array(
			'selector' => Bizline_Helper::with_prefix_selector( '.pagination .nav-links > *.current, ::selection, %s-main-menu > ul > li > a:after, %s-btn-primary, #infinite-handle span, .woocommerce ul.products li.product .button, .woocommerce ul.products li.product .added_to_cart.wc-forward, .search-form button, %s-button-primary,%s-section-title.title-line-before:before, .widget .woocommerce-product-search button, .woocommerce #respond input#submit, .woocommerce a.button, .woocommerce button.button, .woocommerce input.button, .single-product .product .entry-summary button.button, .woocommerce-cart .woocommerce form.woocommerce-cart-form table button.button, .woocommerce-cart .woocommerce .cart-collaterals .cart_totals a.checkout-button.button.alt.wc-forward,form.woocommerce-checkout div#order_review #payment button#place_order' ),
			'props' => array(
				'background-color' => 'primary-color',
			)
		),
		array(
			'selector' => Bizline_Helper::with_prefix_selector( '#infinite-handle span, %s-button-primary:before,%s-testimonial-section %s-testimonial-slider-inner .testimonial-position h3 span,%s-services-section %s-services-content %s-services-content-inner %s-services-box-inner > div h3 a:hover, %s-news-section %s-news-content .news-text h3 a:hover, %s-section-title span, %s-post .post-title a:hover, %s-slider-content %s-slider-content-inner-text h2 span' ),
			'props' => array(
				'color' => 'primary-color',
			)
		),	


		array(
			'selector' => Bizline_Helper::with_prefix_selector(  '%s-arrow svg:hover' ),
			'props' => array(
				'fill' => 'primary-color',
			)
		),


		array(
			'selector' => Bizline_Helper::with_prefix_selector(  '.post-content-wrap .post-categories li a:hover, %s-post .entry-content-stat + a:hover, %s-post %s-comments a:hover, .pagination .nav-links > *, body .post-categories li a' ),
			'props' => array(
				'color' => 'primary-color',
			)
		),
		array(
			'selector' => Bizline_Helper::with_prefix_selector( '.pagination .nav-links > *, %s-post.sticky' ),
			'props' => array(
				'border-color' => 'primary-color',
			)
		),

		#secondary color

		array(
			'selector' => Bizline_Helper::with_prefix_selector( '%s-top-bar, %s-get-quote-section, %s-services-section %s-more-service-btn %s-button-primary:before, %s-services-section %s-more-service-btn %s-button-primary:after,%s-news-section .news-more-btn:after, %s-news-section .news-more-btn:before, .single-product .product .onsale,.woocommerce ul.products li.product .onsale,.footer-widget .widget-title:after' ),
			'props' => array(
				'background' => 'secondary-color',
			)
		),

		#header bg color 	

		array(
			'selector' => Bizline_Helper::with_prefix_selector( '%s-site-header' ),
			'props' => array(
				'background-color' => 'header-bg-color',
			)
		),		


		#header icon color

		array(
			'selector' => Bizline_Helper::with_prefix_selector( '%s-bottom-header-wrapper %s-header-icons %s-search-icon, a.cart-icon, a.cart-icon:visited, %s-bottom-header-wrapper %s-header-icons %s-search-icon:visited' ),
			'props' => array(
				'color' => 'header-icon-color',
			)
		),		

		array(
			'selector' => Bizline_Helper::with_prefix_selector( 'a.cart-icon span, .menu-toggler span' ),
			'props' => array(
				'background' => 'header-icon-color',
			)
		),	

		#btn hover bg color		

		array(
			'selector' => Bizline_Helper::with_prefix_selector( '%s-button-primary:hover, .widget .woocommerce-product-search button:hover,.woocommerce #respond input#submit:hover, .woocommerce a.button:hover, .woocommerce button.button:hover, .woocommerce input.button:hover, .single-product .product .entry-summary button.button:hover, .woocommerce ul.products li.product .button:hover, .woocommerce-cart .woocommerce form.woocommerce-cart-form table button.button:hover,.woocommerce-cart .woocommerce .cart-collaterals .cart_totals a.checkout-button.button.alt.wc-forward:hover,form.woocommerce-checkout div#order_review #payment button#place_order:hover, .search-form button:hover' ),
			'props' => array(
				'background' => 'btn-hover-bg-color',
			)
		),	

		# Typography
		array(
			'selector' => '.site-branding .site-title, .site-branding .site-description, .site-title a',
			'props'    => array(
				'font-family' => 'site-info-font'
			)
		),
		array(
			'selector' => 'body',
			'props'    => array(
				'font-family' => 'body-font'
			)
		),
		array(
			'selector'  => 'h1, h2, h3, h4, h5, h6, h1 a, h2 a, h3 a, h4 a, h5 a, h6 a',
			'props'	=> array(
				'font-family' => 'heading-font',
			),
		),
		# Color Options
		array(
			'selector'  => 'body, body p, body div, .woocommerce-Tabs-panel, div#tab-description, .woocommerce-tabs.wc-tabs-wrapper',
			'props'		=> array(
				'color' => 'body-paragraph-color',
			),
		),
		array(
			'selector'  => Bizline_Helper::with_prefix_selector( '%s-main-menu > ul > li > a' ),
			'props'		=> array(
				'color' => 'primary-menu-item-color',
			),
		),
		array(
			'selector'  => 'body a, body a:visited',
			'props'		=> array(
				'color' => 'link-color',
			),
		),
		array(
			'selector'  => 'body a:hover',
			'props'		=> array(
				'color' => 'link-hover-color',
			),
		),
		array(
			'selector'  => '#secondary .widget-title',
			'props'		=> array(
				'color' => 'sb-widget-title-color',
			),
		),		
		array(
			'selector'  => '#secondary .widget, #secondary .widget a, #secondary .widget ul li a',
			'props'		=> array(
				'color' => 'sb-widget-content-color',
			),
		),
		array(
			'selector'  => '.footer-widget .widget-title',
			'props'		=> array(
				'color' => 'footer-title-color',
			),
		),
		array(
			'selector'  => '.footer-top-section',
			'props'		=> array(
				'background-color' => 'footer-top-background-color',
			),
		),		
		array(
			'selector'  => '.footer-bottom-section',
			'props'		=> array(
				'background-color' => 'footer-copyright-background-color',
			),
		),		
		array(
			'selector'  => '.footer-widget, .footer-widget p, .footer-widget span, .footer-widget ul li a,  #calendar_wrap #wp-calendar th, #calendar_wrap td, #calendar_wrap caption, #calendar_wrap td a,  .footer-widget ul li',
			'props'		=> array(
				'color' => 'footer-content-color',
			),
		),
		array(
			'selector'  => '.footer-bottom-section span, .footer-bottom-section .credit-link',
			'props'		=> array(
				'color' => 'footer-copyright-text-color',
			),
		),		
		# inner banner
		array(
			'selector' => Bizline_Helper::with_prefix_selector( '%s-inner-banner-wrapper:after' ),
			'props'    => array(
				'background-color' => 'ib-background-color'
			)
		),
		array(
			'selector' => Bizline_Helper::with_prefix_selector( '%s-inner-banner-wrapper %s-inner-banner .entry-title' ),
			'props'    => array(
				'color' => 'ib-title-color'
			)
		),
		# Breadcrumb
		array(
			'selector'  => '.wrap-breadcrumb ul.trail-items li a:after',
			'props'		=> array(
				'content' => 'bc-separator',
			),
		),
		array(
			'selector'  => '.wrap-breadcrumb ul li a, .wrap-breadcrumb ul li span, .taxonomy-description p',
			'props'		=> array(
				'color' => 'ib-title-color'
			),
		),
	);

	Bizline_Css::add_styles( $style, 'md' );
}