<?php
/**
* Register home page feature options
*
* @return void
* @since 1.0.0
*
* @package Bizline WordPress theme
*/

if( !function_exists( 'bizline_acb_front_feature' ) ):
    /**
    * Active callback function of header top bar
    *
    * @static
    * @access public
    * @return boolen
    * @since 1.0.0
    *
    * @package Bizline WordPress theme
    */
    function bizline_acb_front_feature( $control ){
        $value = $control->manager->get_setting( Bizline_Helper::with_prefix( 'home-feature-status' ) )->value();
        return $value;
    }
endif;

function bizline_front_page_feature_options(){ 
    Bizline_Customizer::set(array(
        # Front Page option
        'panel' => array(
            'id'       => 'front-panel'
        ),
        # Front Page Option > Feature
        'section' => array(
            'id'    => 'home-feature',
            'title' => esc_html__( 'Feature','bizline' ),
            'priority' => 5
        ),
        # Front Page Option > Feature > settings
        'fields'  => array(
            array(
                'id'      => 'home-feature-status',
                'label'   => esc_html__( 'Enable', 'bizline' ),
                'default' => false,
                'type'    => 'toggle',
            ),
            array(
                'id'      => 'home-feature-title-page',
                'label'   => esc_html__( 'Title', 'bizline' ),
                'description' => esc_html__( 'Select page for section title and description', 'bizline' ),
                'default' => 0,
                'active_callback' => 'acb_front_feature',
                'type'    => 'dropdown-pages',
            ),
            array(
                'id'      => 'home-feature-excerpt-length',
                'label'   => esc_html__( 'Excerpt Length', 'bizline' ),
                'default' => 30,
                'active_callback' => 'acb_front_feature',
                'type'    => 'number',
            ),
            array(
              'id'    => 'feature-pages',
              'label' => esc_html__( 'Select Pages', 'bizline' ),
              'type'  => 'repeater',
              'active_callback' => 'acb_front_feature',
              'limit' => 6,
              'repeat' => array(
                'page' => array(
                    'label' => '',
                )
              ),
            ),
        ),
    ));
}
add_action( 'init', 'bizline_front_page_feature_options' );