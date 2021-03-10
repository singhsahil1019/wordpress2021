<?php
/**
* Register breadcrumb Options
*
* @return void
* @since 1.0.0
*
* @package Bizline WordPress theme
*/
function bizline_color_options(){	
	Bizline_Customizer::set(array(
		# Theme option
		'panel' => 'panel',
		# Theme Option > color options
		'section' => array(
		    'id'       => 'color-section',
		    'title'    => esc_html__( 'Color Options' ,'bizline' ),
		    'priority' => 5
		),
		'fields'  =>array(
			array(
				'id'      => 'primary-color',
				'label'   => esc_html__( 'Primary Color', 'bizline' ),
				'default' => '#0099cc',
				'type'    => 'color-picker',
			),
			array(
				'id'      => 'secondary-color',
				'label'   => esc_html__( 'Secondary Color', 'bizline' ),
				'default' => '#66ccff',
				'type'    => 'color-picker',
			),
			array(
				'id'      => 'body-paragraph-color',
				'label'   => esc_html__( 'Body Text Color', 'bizline' ),
				'default' => '#5f5f5f',
				'type'    => 'color-picker',
			),
			array(
				'id'      => 'primary-menu-item-color',
				'label'   => esc_html__( 'Primary Menu Item Color', 'bizline' ),
				'default' => '#000',
				'type'    => 'color-picker',
			),

			array(
				'id'      => 'header-bg-color',
				'label'   => esc_html__( 'Header Background Color', 'bizline' ),
				'default' => '#fff',
				'type'    => 'color-picker',
			),

			array(
				'id'      => 'header-icon-color',
				'label'   => esc_html__( 'Header Icon Color', 'bizline' ),
				'default' => '#000',
				'type'    => 'color-picker',
			),

			array(
				'id'      => 'btn-hover-bg-color',
				'label'   => esc_html__( 'Button Hover Background Color', 'bizline' ),
				'default' => '#003399',
				'type'    => 'color-picker',
			),

			array(
				'id'   => 'line-1',
				'type' => 'horizontal-line',
			),
			array(
				'id'      => 'link-color',
				'label'   => esc_html__( 'Link Color', 'bizline' ),
				'default' => '#145fa0',
				'type'    => 'color-picker',
			),
			array(
				'id'      => 'link-hover-color',
				'label'   => esc_html__( 'Link Hover Color', 'bizline' ),
				'default' => '#737373',
				'type'    => 'color-picker',
			),
			array(
				'id'   => 'line-2',
				'type' => 'horizontal-line',
			),
			array(
				'id'      => 'sb-widget-title-color',
				'label'   => esc_html__( 'Sidebar Widget Title Color', 'bizline' ),
				'default' => '#000000',
				'type'    => 'color-picker',
			),
			array(
				'id'      => 'sb-widget-content-color',
				'label'   => esc_html__( 'Sidebar Widget Content Color', 'bizline' ),
				'default' => '#282835',
				'type'    => 'color-picker',
			),
			array(
				'id'   => 'line-3',
				'type' => 'horizontal-line',
			),
			array(
				'id'      => 'footer-title-color',
				'label'   => esc_html__( 'Footer Widget Title Color', 'bizline' ),
				'default' => '#000',
				'type'    => 'color-picker',
			),
			array(
				'id'      => 'footer-content-color',
				'label'   => esc_html__( 'Footer Widget Content Color', 'bizline' ),
				'default' => '#4f4f4f',
				'type'    => 'color-picker',
			),
			array(
				'id'   => 'line-4',
				'type' => 'horizontal-line',
			),
			array(
				'id'      => 'footer-top-background-color',
				'label'   => esc_html__( 'Footer Background Color', 'bizline' ),
				'default' => '#f2f2f2',
				'type'    => 'color-picker',
			),
			array(
				'id'      => 'footer-copyright-background-color',
				'label'   => esc_html__( 'Footer Copyright Background Color', 'bizline' ),
				'default' => '#dddddd',
				'type'    => 'color-picker',
			),
			array(
				'id'      => 'footer-copyright-text-color',
				'label'   => esc_html__( 'Footer Copyright Text Color', 'bizline' ),
				'default' => '#424242',
				'type'    => 'color-picker',
			),
		),			
	));
}
add_action( 'init', 'bizline_color_options' );